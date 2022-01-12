#This is an example file and should not be used as is
#Assumptions

aws_credentials_file = "/Users/someperson/.aws/credentials" #full path to credentials file
aws_profile          = "WhizBangEnvronment"                 #in the above credentials file, the provile to use
aws_region           = "us-east-2"                          #the AWS region to taget
create_bastion       = false                                # whether or not to create a bastion and allow public access to it, should only be true for persona/dev environments

project = "whizbang" #Project, should be lowercase and descriptive of the deploy purpose... becomes part of resource names


environment_configuration = {

  #private subnet ids, can be 1 to many.  Will become where the container can run
  subnets_private = [
    "subnet-12345678901234560",
    "subnet-09835640540544884",
  ]

  #public subnets, can be 1 to many.  Will become where the ALB lives and have port 443 open to it publicly
  subnets_public = [
    "subnet-0c862dee6a75856bb",
    "subnet-0e587cf47ad1c0f5a",
  ]

  # the target VPC
  vpc_id = [
    "vpc-0544645a8fff23880",
  ]

  #Full arm to the Amazon Certificate Manager key
  alb_ssl_cert_arn = ["arn:aws:acm:us-east-2:1212121212:certificate/3a915f8r-6701-40bf-a56e-b63cc17b526e"]
  #The full domain name that will be used to access rundeck
  domain_name = ["qa.rundeck.encoretesting.com"]
  #Environment label, will be used in resource names and tags  
  environment_name = ["qa"]
  #This is the api key you want to use to protect webhooks on rundeck
  rundeck_webhook_api_key = ["30942317-EC1B-4121-9654-A339FA52FC8A"]
  #Some value you want to use for this environment for storage encryption
  rundeck_storage_converter_password = ["165eb30cb7e70430"]
  #If false, no public Security group rules will form.
  externally_accessible = ["true"]
  #Allow port 80 access to Rundeck?  Should be false.
  allow_incoming_port_80 = ["false"]
  #ALB blocks access to Rundeck's login page, there may be cases where we want to login with a local Rundeck account.
  bypass_login_redirect_value = ["LetMeIn"]
}

#This is only used for bastion specs
ec2_configuration = {
  instance_type = ["t3.small"]
  volume_type   = ["gp3"]
  volume_size   = [20]
  key_name      = ["EC2Key"]
}

#configuration for RDS creation.  Pretty self explanatory.
#currently hardcode to a db.t3.small
rds_configuration = {
  db_name      = "rundeckDB"
  db_username  = "rundeckUser"
  db_password  = "rundeckPassword"
  storage_size = 20
}

#Fargate/ECS config
ecs_configuration = {
  #Repo username and password for private repo
  docker_repo_username = "username"
  docker_repo_password = "password"
  #image to be used
  docker_repo_image = "repo image and tag"
  #CPU and Memory config for FARGATE/ECS service/task
  #Only allows certain configurations
  service_cpu    = 1024
  service_memory = "3072"
  #Where to mount the EFS volume in the container.
  shared_files_path = "/sharedfiles"
  #enable ECS Exec (settings and permissions are set)
  ecs_exec_enabled = false
}

#Values for SSO, map to environment variables.
sso_configuration = {
  client_id        = "Client ID in ADFS, some guid"
  client_secret    = "Client secret in ADFS, some guid that's only available during creation"
  auth_url         = "https://<someurl>/adfs/oauth2/authorize/"
  token_url        = "https://<someurl>/adfs/oauth2/token/"
  logout_url       = "https://<someurl>/adfs/oauth2/logout"
  relying_party_id = "<whatever is setup in ADFS>"
  vouch_delay      = "65"
}