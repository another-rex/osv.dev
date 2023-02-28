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
"""Handlers for the OSV web frontend."""

import json
import os
import math
import re
import types
import typing

from flask import abort
from flask import current_app
from flask import Blueprint
from flask import make_response
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
import markdown2
from urllib import parse
from google.cloud import ndb

import cache
import osv
import rate_limiter
import source_mapper
import utils

blueprint = Blueprint('frontend_handlers', __name__)

_PAGE_SIZE = 16
_PAGE_LOOKAHEAD = 4
_REQUESTS_PER_MIN = 30
_WORD_CHARACTERS_OR_DASH = re.compile(r'^[\w-]+$')
_VALID_BLOG_NAME = _WORD_CHARACTERS_OR_DASH
_VALID_VULN_ID = _WORD_CHARACTERS_OR_DASH
_BLOG_CONTENTS_DIR = 'blog'

if utils.is_prod():
  redis_host = os.environ.get('REDISHOST', 'localhost')
  redis_port = int(os.environ.get('REDISPORT', 6379))
  limiter = rate_limiter.RateLimiter(
      redis_host, redis_port, requests_per_min=_REQUESTS_PER_MIN)

  @blueprint.before_request
  def check_rate_limit():
    ip_addr = request.headers.get('X-Appengine-User-Ip', 'unknown')
    if not limiter.check_request(ip_addr):
      abort(429)


def _load_blog_content(name):
  """Load blog content."""
  path = os.path.join(current_app.static_folder, _BLOG_CONTENTS_DIR, name)
  if not os.path.exists(path):
    abort(404)
    return None

  with open(path) as handle:
    return handle.read()


@blueprint.before_request
def check_cors_preflight():
  """Handle CORS preflight requests."""
  if request.method != 'OPTIONS':
    return None

  response = make_response()
  response.headers.add('Access-Control-Allow-Origin', 'http://localhost:8080')
  response.headers.add('Access-Control-Allow-Methods', '*')
  response.headers.add('Access-Control-Allow-Headers', '*')
  return response


@blueprint.after_request
def add_cors_headers(response):
  """Add CORS headers."""
  response.headers.add('Access-Control-Allow-Origin', 'http://localhost:8080')
  return response


@blueprint.route('/v2/')
def index_v2():
  return redirect('/')


@blueprint.route('/v2/<path:subpath>')
def index_v2_with_subpath(subpath):
  return redirect('/' + subpath)


@blueprint.route('/')
def index():
  return render_template(
      'home.html', ecosystem_counts=osv_get_ecosystem_counts_cached())


@blueprint.route('/blog/', strict_slashes=False)
def blog():
  return render_template('blog.html', index=_load_blog_content('index.html'))


@blueprint.route('/blog/index.xml')
def blog_rss():
  return current_app.send_static_file(
      os.path.join(_BLOG_CONTENTS_DIR, 'index.xml'))


@blueprint.route('/blog/posts/<blog_name>/', strict_slashes=False)
def blog_post(blog_name):
  if not _VALID_BLOG_NAME.match(blog_name):
    abort(404)
    return None

  return render_template(
      'blog_post.html',
      content=_load_blog_content(
          os.path.join('posts', blog_name, 'index.html')))


@blueprint.route('/about')
def about():
  return render_template('about.html')


@blueprint.route('/list-autocomplete')
def list_vulnerabilities_autocomplete():
  query = request.args.get('q', '')
  ecosystem = request.args.get('ecosystem', '')

  is_turbo_frame = request.headers.get('Turbo-Frame')
  # Redirect back to main page if not a turbo frame
  # This should happen very rarely
  if not is_turbo_frame:
    return redirect('/list?ecosystem=' + ecosystem, code=302)

  if (len(query) < 2):
    return render_template('search_box.html')

  results = osv_autocomplete_query(query, 5, False, ecosystem)

  return render_template(
      'search_box.html',
      query=query,
      ecosystem=ecosystem,
      vulnerabilities=results['items'],
      projects=results['projects'],
  )


@blueprint.route('/list')
def list_vulnerabilities():
  """Main page."""
  is_turbo_frame = request.headers.get('Turbo-Frame')

  # Remove page parameter if not from turbo frame
  if not is_turbo_frame:
    if request.args.get('page', 1) != 1:
      q = parse.parse_qs(request.query_string)
      q.pop(b'page', None)
      return redirect(
          url_for(request.endpoint) + '?' + parse.urlencode(q, True))

  query = request.args.get('q', '')
  page = int(request.args.get('page', 1))
  ecosystem = request.args.get('ecosystem')
  results = osv_query(query, page, _PAGE_SIZE, False, ecosystem)

  # Fetch ecosystems by default. As an optimization, skip when rendering page
  # fragments.
  ecosystem_counts = osv_get_ecosystem_counts_cached(
  ) if not is_turbo_frame else None

  return render_template(
      'list.html',
      page=page,
      total_pages=math.ceil(results['total'] / _PAGE_SIZE),
      query=query,
      selected_ecosystem=ecosystem,
      ecosystem_counts=ecosystem_counts,
      vulnerabilities=results['items'])


@blueprint.route('/vulnerability/<vuln_id>')
def vulnerability(vuln_id):
  """Vulnerability page."""
  vuln = osv_get_by_id(vuln_id)
  return render_template('vulnerability.html', vulnerability=vuln)


@blueprint.route('/<potential_vuln_id>')
def vulnerability_redirector(potential_vuln_id):
  """Convenience redirector for /VULN-ID to /vulnerability/VULN-ID."""
  if not _VALID_VULN_ID.match(potential_vuln_id):
    abort(404)
    return None

  vuln = osv_get_by_id(potential_vuln_id)
  if vuln:
    return redirect(f'/vulnerability/{potential_vuln_id}')

  abort(404)
  return None


def bug_to_response(bug, detailed=True):
  """Convert a Bug entity to a response object."""
  response = osv.vulnerability_to_dict(bug.to_vulnerability())
  response.update({
      'isFixed': bug.is_fixed,
      'invalid': bug.status == osv.BugStatus.INVALID
  })
  print(response)

  if detailed:
    add_links(response)
    add_source_info(bug, response)
    add_related_aliases(bug, response)
  return response


def add_links(bug):
  """Add VCS links where possible."""

  for entry in bug.get('affected', []):
    for i, affected_range in enumerate(entry.get('ranges', [])):
      affected_range['id'] = i
      if affected_range['type'] != 'GIT':
        continue

      repo_url = affected_range.get('repo')
      if not repo_url:
        continue

      for event in affected_range.get('events', []):
        if event.get('introduced'):
          event['introduced_link'] = _commit_to_link(repo_url,
                                                     event['introduced'])
          continue

        if event.get('fixed'):
          event['fixed_link'] = _commit_to_link(repo_url, event['fixed'])
          continue

        if event.get('limit'):
          event['limit_link'] = _commit_to_link(repo_url, event['limit'])
          continue


def add_source_info(bug, response):
  """Add source information to `response`."""
  if bug.source_of_truth == osv.SourceOfTruth.INTERNAL:
    response['source'] = 'INTERNAL'
    return

  source_repo = osv.get_source_repository(bug.source)
  if not source_repo or not source_repo.link:
    return

  source_path = osv.source_path(source_repo, bug)
  response['source'] = source_repo.link + source_path
  response['source_link'] = response['source']


def add_related_aliases(bug: osv.Bug, response):
  """Add links to other osv entries that's related through aliases"""
  # Add links to other entries if they exist
  aliases = {}
  if bug.aliases:
    directly_refed = osv.Bug.query(osv.Bug.db_id.IN(bug.aliases))
    is_directly_refed = {dr.db_id for dr in directly_refed}
    for alias in bug.aliases:
      aliases[alias] = {
          'exists': alias in is_directly_refed,
          'same_alias_entries': []
      }

  # Add links to other entries that have the same alias or references this
  query = osv.Bug.query(osv.Bug.aliases.IN(bug.aliases + [bug.id()]))
  for other in query:
    if other.id() == bug.id():
      continue
    for other_alias in other.aliases:
      if other_alias in aliases:
        aliases[other_alias]['same_alias_entries'].append(other.id())
    if bug.id() in other.aliases:
      aliases[other.id()] = {'exists': True, 'same_alias_entries': []}

  # Remove self if it was added
  aliases.pop(bug.id(), None)

  response['aliases'] = [{
      'alias_id': aid,
      'exists': ex['exists'],
      'same_alias_entries': ex['same_alias_entries']
  } for aid, ex in aliases.items()]


def _commit_to_link(repo_url, commit):
  """Convert commit to link."""
  vcs = source_mapper.get_vcs_viewer_for_url(repo_url)
  if not vcs:
    return None

  if ':' not in commit:
    return vcs.get_source_url_for_revision(commit)

  commit_parts = commit.split(':')
  if len(commit_parts) != 2:
    return None

  start, end = commit_parts
  if start == 'unknown':
    return None

  return vcs.get_source_url_for_revision_diff(start, end)


def osv_get_ecosystems():
  """Get list of ecosystems."""
  query = osv.Bug.query(projection=[osv.Bug.ecosystem], distinct=True)
  return sorted([bug.ecosystem[0] for bug in query if bug.ecosystem],
                key=str.lower)


# TODO: Figure out how to skip cache when testing
@cache.instance.cached(
    timeout=24 * 60 * 60, key_prefix='osv_get_ecosystem_counts')
def osv_get_ecosystem_counts_cached():
  """Get count of vulnerabilities per ecosystem, cached"""
  return osv_get_ecosystem_counts()


def osv_get_ecosystem_counts():
  """Get count of vulnerabilities per ecosystem."""
  counts = {}
  ecosystems = osv_get_ecosystems()
  for ecosystem in ecosystems:
    if ':' in ecosystem:
      # Count by the base ecosystem index. Otherwise we'll overcount as a
      # single entry may refer to multiple sub-ecosystems.
      continue

    counts[ecosystem] = osv.Bug.query(
        osv.Bug.ecosystem == ecosystem,
        osv.Bug.public == True,  # pylint: disable=singleton-comparison
        osv.Bug.status == osv.BugStatus.PROCESSED).count()

  filtered_counts = {key: elem for key, elem in counts.items() if elem > 0}
  return filtered_counts


def osv_autocomplete_query(search_string: str, page_size: int,
                           affected_only: bool, ecosystem: str):

  project_query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                                osv.Bug.public == True)  # pylint: disable=singleton-comparison

  id_query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                           osv.Bug.public == True)

  if not search_string:
    raise ValueError("search_string is empty or none")

  lower_search_str = search_string.lower()
  lower_search_str_inc = lower_search_str[:-1] + chr(
      ord(lower_search_str[-1]) + 1)

  # Build query for the package name
  project_query = project_query.filter(osv.Bug.project >= lower_search_str)
  project_query = project_query.filter(osv.Bug.project < lower_search_str_inc)

  project_query.distinct_on = ["project", "ecosystem"]
  project_query.projection = ["project", "ecosystem"]

  # Build query for the vulnerability IDs
  id_query = id_query.filter(osv.Bug.search_indices >= lower_search_str)
  id_query = id_query.filter(osv.Bug.search_indices < lower_search_str_inc)

  id_query = id_query.order(-osv.Bug.search_indices)

  if affected_only:
    project_query = project_query.filter(osv.Bug.has_affected == True)  # pylint: disable=singleton-comparison
    id_query = id_query.filter(osv.Bug.has_affected == True)  # pylint: disable=singleton-comparison

  if ecosystem:
    project_query = project_query.filter(osv.Bug.ecosystem == ecosystem)
    id_query = id_query.filter(osv.Bug.ecosystem == ecosystem)
    # Don't do distinct or projection on ecosystem,
    # since ecosystem will be exactly one value now (and is not supported by datastore)
    project_query.projection = ["project"]
    project_query.distinct_on = ["project"]

  results = {
      'items': [],
      'projects': [],
  }

  bugs_search_idx: ndb.Future = id_query.fetch_page_async(page_size=page_size)
  bugs = project_query.fetch()

  project_query_results: typing.List[types.SimpleNamespace] = []

  for bug in bugs:
    entry = types.SimpleNamespace()
    if ecosystem:
      entry.ecosystem = ecosystem
    else:
      entry.ecosystem = osv.impact.ecosystems.normalize(bug.ecosystem[0])
    entry.project = bug.project[0]
    project_query_results.append(entry)

  # Unique on the first ecosystem entry, for ecosystems with sub ecosystems (e.g. Alpine:3.8)
  # the first ecosystem will always be the overall ecosystem (e.g. Alpine)
  seen = set()
  project_query_results = [
      seen.add(bug.ecosystem) or bug
      for bug in project_query_results
      if bug.ecosystem not in seen
  ]

  project_count_futures: typing.List[ndb.Future] = []
  for bug in project_query_results:
    project_count_futures.append(
        osv.Bug.query(osv.Bug.project == bug.project,
                      osv.Bug.ecosystem == bug.ecosystem).count_async())

  ndb.Future.wait_all(project_count_futures)

  for bug, future in zip(project_query_results, project_count_futures):
    bug.count = future.get_result()
    results['projects'].append(bug)

  # Sort descending by number of vulnerabilities
  results['projects'].sort(key=lambda x: -x.count)
  results['projects'] = results['projects'][:page_size]

  results['items'], _, _ = bugs_search_idx.get_result()

  return results


def osv_query(search_string: str, page: int, page_size: int,
              affected_only: bool, ecosystem: str):
  """Run an OSV query."""
  query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                        osv.Bug.public == True)  # pylint: disable=singleton-comparison

  if search_string:
    query = query.filter(
        osv.Bug.search_indices == search_string.lower().strip('-'))

  if affected_only:
    query = query.filter(osv.Bug.has_affected == True)  # pylint: disable=singleton-comparison

  if ecosystem:
    query = query.filter(osv.Bug.ecosystem == ecosystem)

  query = query.order(-osv.Bug.last_modified)
  total = query.count()
  results = {
      'total': total,
      'items': [],
  }

  bugs, _, _ = query.fetch_page(
      page_size=page_size, offset=(page - 1) * page_size)
  for bug in bugs:
    results['items'].append(bug_to_response(bug, detailed=False))

  return results


def osv_get_by_id(vuln_id):
  """Gets bug details from its id. If invalid, aborts the request."""
  if not vuln_id:
    abort(400)
    return None

  bug = osv.Bug.get_by_id(vuln_id)
  if not bug:
    abort(404)
    return None

  if bug.status == osv.BugStatus.UNPROCESSED:
    abort(404)
    return None

  if not bug.public:
    abort(403)
    return None

  return bug_to_response(bug)


@blueprint.app_template_filter('event_type')
def event_type(event):
  """Get the type from an event."""
  if event.get('introduced'):
    return 'Introduced'
  if event.get('fixed'):
    return 'Fixed'
  if event.get('limit'):
    return 'Limit'
  if event.get('last_affected'):
    return 'Last affected'

  return None


@blueprint.app_template_filter('event_link')
def event_link(event):
  """Get the link from an event."""
  if event.get('introduced_link'):
    return event['introduced_link']
  if event.get('fixed_link'):
    return event['fixed_link']
  if event.get('limit_link'):
    return event['limit_link']
  if event.get('last_affected_link'):
    return event['last_affected_link']

  return None


@blueprint.app_template_filter('event_value')
def event_value(event):
  """Get the value from an event."""
  if event.get('introduced'):
    return event['introduced']
  if event.get('fixed'):
    return event['fixed']
  if event.get('limit'):
    return event['limit']
  if event.get('last_affected'):
    return event['last_affected']

  return None


@blueprint.app_template_filter('should_collapse')
def should_collapse(affected):
  """Whether if we should collapse the package tab bar."""
  total_package_length = sum(
      len(entry.get('package', {}).get('name', '')) for entry in affected)
  return total_package_length > 70 or len(affected) > 5


@blueprint.app_template_filter('group_versions')
def group_versions(versions):
  """Group versions by prefix."""
  groups = {}

  for version in sorted(versions):
    if '.' not in version:
      groups.setdefault('Other', []).append(version)
      continue

    label = version.split('.')[0] + '.*'
    groups.setdefault(label, []).append(version)

  return groups


@blueprint.app_template_filter('markdown')
def markdown(text):
  """Render markdown."""
  if text:
    return markdown2.markdown(
        text, safe_mode='escape', extras=['fenced-code-blocks'])

  return ''


@blueprint.app_template_filter('display_json')
def display_json(data):
  # We can't use the default `tojson` filter as it's intended for code (and
  # escapes characters like '<' to '\u003c'). We want to render the JSON for
  # display purposes and use HTML escaping ('&lt;') instead so it's rendered
  # as '<'.
  return json.dumps(data, indent=4)


@blueprint.app_template_filter('log')
def logarithm(n):
  return math.log(n)
