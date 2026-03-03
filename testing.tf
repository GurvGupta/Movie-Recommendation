provider "google" {
  project = "your-project-id"
  region  = "us-central1"
}

# VIOLATION 1: Publicly accessible bucket (No IAM prevention)
# VIOLATION 2: Missing encryption (using Google-managed instead of CSEK/CMEK)
resource "google_storage_bucket" "insecure_bucket" {
  name          = "my-very-insecure-data-bucket"
  location      = "US"
  force_destroy = true

  # This allows the bucket to be public if someone adds an 'allUsers' IAM binding
  public_access_prevention = "inherited" 
}

# VIOLATION 3: Public IP address assigned to an instance
# VIOLATION 4: Default Service Account used (too many permissions)
# VIOLATION 5: IP Forwarding enabled (security risk)
resource "google_compute_instance" "vulnerable_vm" {
  name         = "dev-instance-01"
  machine_type = "n1-standard-1"
  zone         = "us-central1-a"
  can_ip_forward = true # Policy Violation: Usually restricted

  boot_disk {
    initialize_params {
      image = "debian-cloud/debian-11"
    }
  }

  network_interface {
    network = "default"

    # The presence of this block assigns a Public IP
    access_config {
      // Ephemeral public IP
    }
  }

  # Policy Violation: Using the default compute service account
  # Most policies require a custom SA with Least Privilege.
  service_account {
    email  = "123456789-compute@developer.gserviceaccount.com"
    scopes = ["cloud-platform"]
  }
}
