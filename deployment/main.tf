# TODO(michaelkedar): Organise / refactor logically into multiple tf files
# and possibly add variables for some field values.

# APIs
# TODO(michaelkedar): Check whether any required apis are missing.

resource "google_project_service" "compute_engine_api" {
  service = "compute.googleapis.com"
}

resource "google_project_service" "kubernetes_engine_api" {
  service = "container.googleapis.com"
}

# Network

resource "google_compute_subnetwork" "my_subnet_0" {
  name                     = "my-subnet-0"
  network                  = "default"
  ip_cidr_range            = "10.45.32.0/22"
  private_ip_google_access = true
  region                   = "us-central1"
}

resource "google_compute_router" "router" {
  name    = "router"
  network = "default"
  region  = "us-central1"
}

resource "google_compute_router_nat" "nat_config" {
  name                               = "nat-config"
  router                             = google_compute_router.router.name
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  nat_ip_allocate_option             = "AUTO_ONLY"
  region                             = google_compute_router.router.region
}


# Clusters / Node Pools

resource "google_container_cluster" "workers" {
  name       = "workers"
  location   = "us-central1-f"
  subnetwork = google_compute_subnetwork.my_subnet_0.self_link

  private_cluster_config {
    enable_private_endpoint = false
    enable_private_nodes    = true
    master_ipv4_cidr_block  = "172.16.0.32/28"
  }

  # We need to define this for private clusters, but all fields are optional.
  ip_allocation_policy {}

  provider = google-beta
  addons_config {
    gce_persistent_disk_csi_driver_config {
      enabled = true
    }
  }

  # We can't create a cluster with no node pool defined, but we want to only use
  # separately managed node pools. So we create the smallest possible default
  # node pool and immediately delete it.
  remove_default_node_pool = true
  initial_node_count       = 1
}

resource "google_container_node_pool" "default_pool" {
  name     = "default-pool"
  cluster  = google_container_cluster.workers.name
  location = google_container_cluster.workers.location

  autoscaling {
    min_node_count = 1
    max_node_count = 1000
  }


  node_config {
    machine_type    = "n1-highmem-2"
    disk_type       = "pd-ssd"
    disk_size_gb    = 64
    local_ssd_count = 1

    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

  }
}

resource "google_container_node_pool" "highend" {
  name     = "highend"
  cluster  = google_container_cluster.workers.name
  location = google_container_cluster.workers.location

  autoscaling {
    min_node_count = 0
    max_node_count = 100
  }


  node_config {
    machine_type    = "n1-standard-32"
    disk_type       = "pd-standard"
    disk_size_gb    = 100
    local_ssd_count = 1

    oauth_scopes = ["https://www.googleapis.com/auth/cloud-platform"]

    labels = {
      workloadType = "highend"
    }

    taint = [{
      effect = "NO_EXECUTE"
      key    = "workloadType"
      value  = "highend"
    }]

  }
}


# Pub/Sub topics

resource "google_pubsub_topic" "tasks" {
  name = "tasks"

  labels = {
    goog-dm = "pubsub"
  }
}

resource "google_pubsub_topic" "failed_tasks" {
  name = "failed-tasks"
}

resource "google_pubsub_subscription" "tasks" {
  name                       = "tasks"
  topic                      = google_pubsub_topic.tasks.id
  message_retention_duration = "604800s"
  ack_deadline_seconds       = 600

  dead_letter_policy {
    dead_letter_topic     = google_pubsub_topic.failed_tasks.id
    max_delivery_attempts = 5
  }

  expiration_policy {
    ttl = "" # never expires
  }

  labels = {
    goog-dm = "pubsub"
  }
}

resource "google_pubsub_topic" "pypi_bridge" {
  name = "pypi-bridge"
}


# Service accounts permissions

data "google_compute_default_service_account" "default" {
}

resource "google_project_iam_member" "compute_service" {
  role   = "roles/editor"
  member = "serviceAccount:${data.google_compute_default_service_account.default.email}"
}

resource "google_service_account" "deployment_service" {
  account_id   = "deployment"
  display_name = "deployment"
}

resource "google_project_iam_member" "deployment_service" {
  role   = "roles/editor"
  member = "serviceAccount:${google_service_account.deployment_service.email}"
}