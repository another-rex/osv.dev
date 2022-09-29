#!/usr/bin/env python3
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""OSV Importer."""
import argparse
import concurrent.futures
import datetime
import functools
import json
import logging
import multiprocessing
import os
import threading
from typing import Tuple

from google.cloud import ndb
from google.cloud import pubsub_v1
from google.cloud import storage
from google.cloud import logging as google_logging
from osv.vulnerability_pb2 import Vulnerability
import pygit2

import osv

DEFAULT_WORK_DIR = '/work'

_BUG_REDO_DAYS = 14
_PROJECT = 'oss-vdb'
_TASKS_TOPIC = 'projects/{project}/topics/{topic}'.format(
    project=_PROJECT, topic='tasks')
_OSS_FUZZ_EXPORT_BUCKET = 'oss-fuzz-osv-vulns'
_EXPORT_WORKERS = 32
_NO_UPDATE_MARKER = 'OSV-NO-UPDATE'
_BUCKET_BATCH_SIZE = 50
_BUCKET_THREAD_POOL = 10


def _is_vulnerability_file(source_repo, file_path):
  """Return whether or not the file is a Vulnerability entry."""
  if (source_repo.directory_path and
      not file_path.startswith(source_repo.directory_path.rstrip('/') + '/')):
    return False

  if source_repo.ignore_file(file_path):
    return False

  return file_path.endswith(source_repo.extension)


def utcnow():
  """utcnow() for mocking."""
  return datetime.datetime.utcnow()


class Importer:
  """Importer."""

  def __init__(self, ssh_key_public_path, ssh_key_private_path, work_dir,
               oss_fuzz_export_bucket):
    self._ssh_key_public_path = ssh_key_public_path
    self._ssh_key_private_path = ssh_key_private_path
    self._work_dir = work_dir
    self._publisher = pubsub_v1.PublisherClient()
    self._oss_fuzz_export_bucket = oss_fuzz_export_bucket

    self._sources_dir = os.path.join(self._work_dir, 'sources')
    os.makedirs(self._sources_dir, exist_ok=True)

  def _git_callbacks(self, source_repo):
    """Get git auth callbacks."""
    return osv.GitRemoteCallback(source_repo.repo_username,
                                 self._ssh_key_public_path,
                                 self._ssh_key_private_path)

  def _request_analysis(self, bug, source_repo, repo):
    """Request analysis."""
    if bug.source_of_truth == osv.SourceOfTruth.SOURCE_REPO:
      path = osv.source_path(source_repo, bug)
      file_path = os.path.join(osv.repo_path(repo), path)
      if not os.path.exists(file_path):
        logging.info(
            'Skipping analysis for %s as the source file no longer exists.',
            path)
        return

      original_sha256 = osv.sha256(file_path)
      self._request_analysis_external(source_repo, original_sha256, path)
    else:
      self._request_internal_analysis(bug)

  def _request_analysis_external(self,
                                 source_repo,
                                 original_sha256,
                                 path,
                                 deleted=False):
    """Request analysis."""
    self._publisher.publish(
        _TASKS_TOPIC,
        data=b'',
        type='update',
        source=source_repo.name,
        path=path,
        original_sha256=original_sha256,
        deleted=str(deleted).lower())

  def _request_internal_analysis(self, bug):
    """Request internal analysis."""
    self._publisher.publish(
        _TASKS_TOPIC,
        data=b'',
        type='impact',
        source_id=bug.source_id,
        allocated_id=bug.key.id())

  def run(self):
    """Run importer."""
    for source_repo in osv.SourceRepository.query():
      if source_repo.name == 'oss-fuzz':
        self.process_oss_fuzz(source_repo)

      self.process_updates(source_repo)

  def checkout(self, source_repo):
    """Check out a source repo."""
    return osv.ensure_updated_checkout(
        source_repo.repo_url,
        os.path.join(self._sources_dir, source_repo.name),
        git_callbacks=self._git_callbacks(source_repo),
        branch=source_repo.repo_branch)

  def import_new_oss_fuzz_entries(self, repo, oss_fuzz_source):
    """Import new entries."""
    exported = []
    for bug in osv.Bug.query(
        osv.Bug.source_of_truth == osv.SourceOfTruth.INTERNAL):
      if bug.status != osv.BugStatus.PROCESSED:
        continue

      if not bug.public:
        continue

      # We don't index this as INTERNAL generally implies OSS-Fuzz anyway (at
      # time of writing).
      source_name, _ = osv.parse_source_id(bug.source_id)
      if source_name != oss_fuzz_source.name:
        continue

      vulnerability_path = os.path.join(
          osv.repo_path(repo), osv.source_path(oss_fuzz_source, bug))
      os.makedirs(os.path.dirname(vulnerability_path), exist_ok=True)
      if os.path.exists(vulnerability_path):
        continue

      logging.info('Writing %s', bug.key.id())
      osv.write_vulnerability(bug.to_vulnerability(), vulnerability_path)
      # The source of truth is now this yaml file.
      bug.source_of_truth = osv.SourceOfTruth.SOURCE_REPO
      exported.append(bug)

    # Commit Vulnerability changes back to the oss-fuzz source repository.
    repo.index.add_all()
    diff = repo.index.diff_to_tree(repo.head.peel().tree)
    if not diff:
      logging.info('No new entries, skipping committing.')
      return

    logging.info('Commiting and pushing new entries')
    if osv.push_source_changes(repo, 'Import from OSS-Fuzz',
                               self._git_callbacks(oss_fuzz_source)):
      ndb.put_multi(exported)

  def schedule_regular_updates(self, repo, source_repo):
    """Schedule regular updates."""
    if (source_repo.last_update_date and
        source_repo.last_update_date >= utcnow().date()):
      return

    for bug in osv.Bug.query(
        osv.Bug.status == osv.BugStatus.PROCESSED,
        osv.Bug.is_fixed == False,  # pylint: disable=singleton-comparison
        osv.Bug.source == source_repo.name):
      self._request_analysis(bug, source_repo, repo)

    # Re-compute existing Bugs for a period of time, as upstream changes may
    # affect results.
    cutoff_time = (utcnow() - datetime.timedelta(days=_BUG_REDO_DAYS))
    query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                          osv.Bug.source == source_repo.name,
                          osv.Bug.timestamp >= cutoff_time)

    for bug in query:
      logging.info('Re-requesting impact for %s.', bug.key.id())
      if not bug.is_fixed:
        # Previous query already requested impact tasks for unfixed bugs.
        continue

      self._request_analysis(bug, source_repo, repo)

    source_repo.last_update_date = utcnow().date()
    source_repo.put()

  def _sync_from_previous_commit(self, source_repo, repo):
    """Sync the repository from the previous commit.

    This was refactored out of _process_updates_git() due to excessive
    indentation.

    Args:
      source_repo: the Git source repository.
      repo: the checked out Git source repository.

    Returns:
      changed_entries: the set of repository paths that have changed.
      deleted_entries: the set of repository paths that have been deleted.
    """
    changed_entries = set()
    deleted_entries = set()

    walker = repo.walk(repo.head.target, pygit2.GIT_SORT_TOPOLOGICAL)
    walker.hide(source_repo.last_synced_hash)

    for commit in walker:
      if commit.author.email == osv.AUTHOR_EMAIL:
        continue

      if _NO_UPDATE_MARKER in commit.message:
        logging.info('Skipping commit %s as no update marker found.', commit.id)
        continue

      logging.info('Processing commit %s from %s', commit.id,
                   commit.author.email)

      for parent in commit.parents:
        diff = repo.diff(parent, commit)
        for delta in diff.deltas:
          if delta.old_file and _is_vulnerability_file(source_repo,
                                                       delta.old_file.path):
            if delta.status == pygit2.GIT_DELTA_DELETED:
              deleted_entries.add(delta.old_file.path)
              continue

            changed_entries.add(delta.old_file.path)

          if delta.new_file and _is_vulnerability_file(source_repo,
                                                       delta.new_file.path):
            changed_entries.add(delta.new_file.path)

    return changed_entries, deleted_entries

  def _process_updates_git(self, source_repo: osv.SourceRepository):
    """Process updates for a git source_repo."""
    logging.info("Begin processing git: %s", source_repo.name)

    repo = self.checkout(source_repo)

    # Get list of changed files since last sync.
    changed_entries = set()
    deleted_entries = set()

    if source_repo.last_synced_hash:
      # Syncing from a previous commit.
      changed_entries, deleted_entries = self._sync_from_previous_commit(
          source_repo, repo)

    else:
      # First sync from scratch.
      logging.info('Syncing repo from scratch')
      for root, _, filenames in os.walk(osv.repo_path(repo)):
        for filename in filenames:
          path = os.path.join(root, filename)
          rel_path = os.path.relpath(path, osv.repo_path(repo))
          if _is_vulnerability_file(source_repo, rel_path):
            changed_entries.add(rel_path)

    # Create tasks for changed files.
    for changed_entry in changed_entries:
      path = os.path.join(osv.repo_path(repo), changed_entry)
      if not os.path.exists(path):
        # Path no longer exists. It must have been deleted in another commit.
        continue

      try:
        _ = osv.parse_vulnerability(path, key_path=source_repo.key_path)
      except Exception as e:
        logging.error('Failed to parse %s: %s', changed_entry, str(e))
        continue

      logging.info('Re-analysis triggered for %s', changed_entry)
      original_sha256 = osv.sha256(path)
      self._request_analysis_external(source_repo, original_sha256,
                                      changed_entry)

    # Mark deleted entries as invalid.
    for deleted_entry in deleted_entries:
      path = os.path.join(osv.repo_path(repo), deleted_entry)
      if os.path.exists(path):
        # Path still exists. It must have been added back in another commit.
        continue

      logging.info('Marking %s as invalid', deleted_entry)
      original_sha256 = ''
      self._request_analysis_external(
          source_repo, original_sha256, deleted_entry, deleted=True)

    source_repo.last_synced_hash = str(repo.head.target)
    source_repo.put()

    logging.info("Finish processing git: %s", source_repo.name)

  def _process_updates_bucket(self, source_repo: osv.SourceRepository):
    """Process updates from bucket."""
    # TODO(ochang): Use Pub/Sub change notifications for more efficient
    # processing.
    logging.info("Begin processing bucket: %s", source_repo.name)

    ignore_last_import_time = source_repo.ignore_last_import_time
    if ignore_last_import_time:
      source_repo.ignore_last_import_time = False
      source_repo.put()

    storage_client = storage.Client()
    # Load bucket index fully to get the total length
    listed_blob_names = [
        blob.name for blob in (storage_client.list_blobs(source_repo.bucket))
    ]
    batched_blob_names = [
        listed_blob_names[i:i + _BUCKET_BATCH_SIZE]
        for i in range(0, len(listed_blob_names), _BUCKET_BATCH_SIZE)
    ]

    # Setup storage client
    def thread_init(func):
      func.client = storage.Client()

    with multiprocessing.Pool(
        _BUCKET_THREAD_POOL,
        initializer=thread_init,
        initargs=(convert_blob_to_vuln,)) as processing_pool:
      for batch_blob in batched_blob_names:
        convert_b = functools.partial(convert_blob_to_vuln, source_repo)
        converted_vulns = processing_pool.map(convert_b, batch_blob)
        # Flatten list[list[]] to list[]
        vulnerabilities = [
            inner for outer in converted_vulns for inner in outer
        ]

        # Batch query the bugs
        vuln_ids = [x.id for x, _, _ in vulnerabilities]
        existing_vulns = osv.Bug.query(osv.Bug.db_id.IN(vuln_ids))

        # Order the data structure to make it easier to match against the queried bugs
        id_mapped_vulns = {x[0].id: x for x in vulnerabilities}

        # Set of vulns [hashes, names] that need to be updated
        need_to_update: set[str, str] = set()
        if not ignore_last_import_time:
          for existing in existing_vulns:
            # Finally expand out the tuple info
            vuln, vuln_hash, blob_name = id_mapped_vulns.pop(existing.db_id)
            if existing.import_last_modified != vuln.modified.ToDatetime():
              need_to_update.add((vuln_hash, blob_name))
            else:
              logging.debug(
                  'Skipping updates for %s as modified date unchanged.',
                  blob_name)

        # Add the rest (either no existing vuln found, or ignoring last_import_time)
        need_to_update.update([
            (vuln_hash, blob_name)
            for _, vuln_hash, blob_name in id_mapped_vulns.values()
        ])

        for (original_sha256, name) in need_to_update:
          self._request_analysis_external(source_repo, original_sha256, name)

    source_repo.last_update_date = utcnow().date()
    source_repo.put()

    logging.info("Finished processing bucket: %s", source_repo.name)

  def process_updates(self, source_repo: osv.SourceRepository):
    """Process user changes and updates."""
    if source_repo.type == osv.SourceRepositoryType.GIT:
      self._process_updates_git(source_repo)
      return

    if source_repo.type == osv.SourceRepositoryType.BUCKET:
      self._process_updates_bucket(source_repo)
      return

    raise RuntimeError('Invalid repo type.')

  def process_oss_fuzz(self, oss_fuzz_source):
    """Process OSS-Fuzz source data."""
    # Export OSS-Fuzz Vulnerability data into source repository.
    # OSS-Fuzz data is first imported via a special Pub/Sub pipeline into OSV.
    # This data needs to be dumped into a publicly accessible/editable place for
    # manual/human editing if required.
    #
    # This then becomes the source of truth where any edits are imported back
    # into OSV.
    repo = self.checkout(oss_fuzz_source)
    self.schedule_regular_updates(repo, oss_fuzz_source)
    self.import_new_oss_fuzz_entries(repo, oss_fuzz_source)
    self.export_oss_fuzz_to_bucket()

  def export_oss_fuzz_to_bucket(self):
    """Export OSS-Fuzz vulns to bucket."""
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(self._oss_fuzz_export_bucket)

    def export_oss_fuzz(vulnerability, testcase_id, issue_id):
      """Export a single vulnerability."""
      try:
        blob = bucket.blob(f'testcase/{testcase_id}.json')
        data = json.dumps(osv.vulnerability_to_dict(vulnerability))
        blob.upload_from_string(data)

        if not issue_id:
          return

        blob = bucket.blob(f'issue/{issue_id}.json')
        blob.upload_from_string(data)
      except Exception as e:
        logging.error('Failed to export: %s', e)

    concurrent.futures.ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=_EXPORT_WORKERS) as executor:
      for bug in osv.Bug.query(osv.Bug.ecosystem == 'OSS-Fuzz'):
        if not bug.public:
          continue

        _, source_id = osv.parse_source_id(bug.source_id)
        executor.submit(export_oss_fuzz, bug.to_vulnerability(), source_id,
                        bug.issue_id)


def convert_blob_to_vuln(source_repo,
                         blob_name) -> list[Tuple[Vulnerability, str, str]]:
  if not _is_vulnerability_file(source_repo, blob_name):
    return []

  logging.debug('Bucket entry triggered for %s/%s', source_repo.bucket,
                blob_name)
  # Use the client variable set in the thread pool initiailizer
  storage_client = convert_blob_to_vuln.client
  bucket = storage_client.bucket(source_repo.bucket)
  blob_bytes = bucket.blob(blob_name).download_as_bytes()
  try:
    vulns = osv.parse_vulnerabilities_from_data(blob_bytes,
                                                os.path.splitext(blob_name)[1])
    hash = osv.sha256_bytes(blob_bytes)
    # Store data needed later on in tuple
    return [(vuln, hash, blob_name) for vuln in vulns]
  except Exception as e:
    logging.error('Failed to parse vulnerability %s: %s', blob_name, e)
    return []


def main():
  logging.getLogger().setLevel(logging.INFO)
  logging.getLogger('google.api_core.bidi').setLevel(logging.ERROR)
  logging.getLogger('google.cloud.pubsub_v1.subscriber._protocol.'
                    'streaming_pull_manager').setLevel(logging.ERROR)

  parser = argparse.ArgumentParser(description='Importer')
  parser.add_argument(
      '--work_dir', help='Working directory', default=DEFAULT_WORK_DIR)
  parser.add_argument('--ssh_key_public', help='Public SSH key path')
  parser.add_argument('--ssh_key_private', help='Private SSH key path')
  args = parser.parse_args()

  tmp_dir = os.path.join(args.work_dir, 'tmp')
  os.makedirs(tmp_dir, exist_ok=True)
  os.environ['TMPDIR'] = tmp_dir

  importer = Importer(args.ssh_key_public, args.ssh_key_private, args.work_dir,
                      _OSS_FUZZ_EXPORT_BUCKET)
  importer.run()


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  logging_client = google_logging.Client()
  logging_client.setup_logging()
  with _ndb_client.context():
    main()
