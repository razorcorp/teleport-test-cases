variable "cidr" {
  description = "VPC CIDR"
}

variable "instance" {
  description = "Instance configuration"
  type = object({
    ami_id: string
    type: string
    size: number
  })
}

variable "tags" {
  description = "Resource tags"
  type = map(string)

  validation {
    condition     = contains(keys(var.tags), "Name")
    error_message = "The 'tags' variable must contain a 'Name' key."
  }
}