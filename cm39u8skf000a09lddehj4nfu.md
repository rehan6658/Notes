---
title: "Building an On-Prem IaC Workflow"
seoTitle: "On-Prem IaC Workflow Guide"
seoDescription: "Learn to build an on-prem Infrastructure as Code (IaC) workflow using Vagrant and Ansible for efficient provisioning and deployment"
datePublished: Sat Nov 09 2024 07:22:31 GMT+0000 (Coordinated Universal Time)
cuid: cm39u8skf000a09lddehj4nfu
slug: building-an-on-prem-iac-workflow
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1731136835681/7ec67177-afab-4f9e-80df-777c288262d8.png
tags: vagrant, ansible, devops, hacking, devsecops, pipeline, ci-cd, cybersecurity-1

---

### Creating an IaC Pipeline

Let’s navigate to the `/home/ubuntu/iac/` directory. All of the scripts we will use today can be found in this directory.

```bash
cd /home/ubuntu/iac/
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731134652082/7da7ca7c-4358-432a-be86-b8c0d5d084d9.png align="center")

### Vagrantfile

Let's start by taking a look at the Vagrantfile:

```bash
cat Vagrantfile
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731134746852/be77aced-7b5c-40ce-a48c-10d920224f2b.png align="center")

```yaml
Vagrant.configure("2") do |config|
  # DB server will be the backend for our website
  config.vm.define "dbserver"  do |cfg|
    # Configure the local network for the server
    cfg.vm.network :private_network, type: "dhcp", docker_network__internal: true
    cfg.vm.network :private_network, ip: "172.20.128.3", netmask: "24"

    # Boot the Docker container and run Ansible
    cfg.vm.provider "docker" do |d|
      d.image = "mysql"
      d.env = {
        "MYSQL_ROOT_PASSWORD" => "mysecretpasswd"
      }
    end
  end


  # Webserver will be used to host our website
  config.vm.define "webserver"  do |cfg|
    # Configure the local network for the server
    cfg.vm.network :private_network, type: "dhcp", docker_network__internal: true
    cfg.vm.network :private_network, ip: "172.20.128.2", netmask: "24"

    # Link the shared folder with the hypervisor to allow data passthrough.
    cfg.vm.synced_folder "./provision", "/tmp/provision"

    # Boot the Docker container and run Ansible
    cfg.vm.provider "docker" do |d|
      d.image = "ansible2"

      d.has_ssh = true

      # Command will keep the container active
      d.cmd = ["/usr/sbin/sshd", "-D"]
    end

    #We will connect using SSH so override the defaults here
    cfg.ssh.username = 'root'
    cfg.ssh.private_key_path = "/home/ubuntu/iac/keys/id_rsa"

    #Provision this machine using Ansible 
    cfg.vm.provision "shell", inline: "ansible-playbook /tmp/provision/web-playbook.yml"
  end
end
```

In this Vagrantfile, we can see that two machines will be provisioned.

**DB Server**

The first machine that will be provisioned is the `dbserver`. Working through the lines of code, we can see that the machine will be added to a local network and receive the IP of `172.20.128.3`. We can also see that the provision directory will be mounted as a share. Lastly, using Docker as the provider, the `mysql` image will be booted and the MySQL password will be configured to be `mysecretpasswd`.

**Web Server**

The second machine that will be provisioned is the `webserver`. Similar to the `dbserver` the machine will be connected to the network and use Docker as its provider. However, there are some slight differences. Firstly, the webserver will expose SSH. Since we are using Docker, we have to alter some of the default Vagrant configurations to allow Vagrant to connect via SSH. This includes changing the username and the private key that will be used for the connection. Secondly, we can see that an Ansible playbook will be executed on the container by looking at the following line:

```yaml
cfg.vm.provision "shell", inline: "ansible-playbook /vagrant/provision/web-playbook.yml"
```

Let's take a look and see what this Ansible playbook will do.

### Ansible Playbook

Let's start by reviewing the `web-playbook.yml` file:

```bash
cat provision/web-playbook.yml
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731134939937/4d934a93-613c-48b6-b027-00a2b24bce50.png align="center")

```yaml
- hosts: localhost
  connection: all
  roles:
    - webapp
```

This is a simple Ansible script that indicates that the webapp role will be provisioned on the host.

To better understand what the webapp role will entail, we can start by reviewing the `~/iac/provision/roles/webapp/tasks/main.yaml` file:

```bash
cat ~/iac/provision/roles/webapp/tasks/main.yaml
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731135016933/ce23af2a-a1ad-45d1-804c-749d7be9e9c8.png align="center")

```yaml
- include_tasks: "db-setup.yml"
- include_tasks: "app-setup.yml"
```

This shows us that there will be two main portions to the Ansible provisioning. At this point, it is worth taking a look as well at the default values in the `~/iac/provision/roles/webapp/defaults/main.yml` file:

```bash
cat ~/iac/provision/roles/webapp/defaults/main.yml
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731135139174/8980c759-9a80-4879-8226-613f29260718.png align="center")

```yaml
db_name: BucketList
db_user: root
db_password: mysecretpasswd
db_host: 172.20.128.3

api_key: superapikey
```

We will get back to these variables in a bit, but keep them in mind.

**DB Setup**

Let's take a look at the `db-setup.yml` file:

```bash
cat ~/iac/provision/roles/webapp/tasks/db-setup.yml
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731135264650/c792457a-87b9-4eda-8cff-b71d31ee4f2b.png align="center")

```yaml
- name: Create temp folder for SQL scripts 
  ansible.builtin.file: 
    path: /tmp/sql state: directory

- name: Time delay to allow SQL server to boot 
    shell: sleep 10

- name: Copy DB creation script with injected variables 
    template: 
      src: templates/createdb.sql 
      dest: /tmp/sql/createdb.sql

- name: Copy DB SP script with injected variables 
    template: 
      src: templates/createsp.sql 
      dest: /tmp/sql/createsp.sql

- name: Create DB 
    shell: mysql -u {{ db_user }} -p{{ db_password }} -h {{ db_host }} < /tmp/sql/createdb.sql

- name: Create Stored Procedures 
    shell: mysql -u {{ db_user }} -p{{ db_password }} -h {{ db_host }} < /tmp/sql/createsp.sql

- name: Cleanup Scripts 
    shell: rm -r /tmp/sql
```

From the script, we can see that 7 tasks will be performed. Reading through these tasks, we can see that a temporary folder will be created where SQL scripts will be pushed to and then executed against the database host.

Let's take a look at how Ansible would inject those variables from before. Take a look at the `Create DB` task's shell command:

```shell
shell: mysql -u {{ db_user }} -p{{ db_password }} -h {{ db_host }} < /tmp/sql/createdb.sql
```

As you can see, the three variables of `db_user`, `db_password`, and `db_host` will be injected using either the values for the default file, or the overwritten values, if they exist.

Ansible allows us to take this a step further. Let's take a look at the actual `createdb.sql` file:

```bash
cat ~/iac/provision/roles/webapp/templates/createdb.sql
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731135448382/f0fbfa16-79ea-4cc7-891e-943862216567.png align="center")

```sql
drop DATABASE IF EXISTS {{ db_name }};

CREATE DATABASE {{ db_name }};
USE {{ db_name }};

drop TABLE IF EXISTS 'tbl_user';

CREATE TABLE {{ db_name }}.tbl_user ( 
  'user_id' BIGINT AUTO_INCREMENT, 
  'user_name' VARCHAR(45) NULL, 
  'user_username' VARCHAR(45) NULL, 
  'user_password' VARCHAR(162) NULL, 
  PRIMARY KEY ('user_id'));
```

As we can see, these variables are even injected into the file templates that will be used. This allows us to control the variables that will be used from a single, centralized location. When we change the user or password that will be used to connect to the database, we can change this in a single location, and it will propagate throughout all provisioning steps for the role.

**Web Setup**

Lastly, let's take a look at the `app-setup.yml` file:

```bash
cat ~/iac/provision/roles/webapp/tasks/app-setup.yml
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731135723785/d7955e49-a108-4151-afed-b23dd25f4e9f.png align="center")

```yaml
- name: Copy web application files
  shell: cp -r /vagrant/provision/roles/webapp/templates/app /

- name: Copy Flask app script with injected variables
  template:
    src: templates/app.py
    dest: /app/app.py
```

This file only has two tasks. The first copies the artifacts required for the web application and the second copies the web application file as a template. A template copy is performed to ensure that the variables, such as the database connection string, are injected into the script as well.

We will not do a deep dive into the rest of the files that will be used for provisioning, however, it is recommended that you take a look at these files to gain a better understanding on what exactly we are provisioning.

### Running the IaC Pipeline

Now that we have an understanding of our pipeline, it is time to start it! Let's start our pipeline and the provisioning using `vagrant up` the `iac` directory. The pipeline will take a while to boot, but pay attention to what is happening.

```bash
vagrant up
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731135950063/13080064-6de8-48f6-b829-afde24461689.png align="center")

> **While you may see some red on the terminal when the Ansible provisioning step is running, as long as these lines only indicate warnings and not an error, the provisioning will complete as expected.**

Once our pipeline has provisioned the machines, we can verify that they are running using the `docker ps` command:

```bash
docker ps
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731136032562/e56c1e14-e1d1-4bea-9d79-134cfd0e41b8.png align="center")

If this is running, we can start our web application using the following command:

```bash
vagrant docker-exec -it webserver -- python3 /app/app.py
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731136183092/9981019a-d582-44f6-8713-4511788932d0.png align="center")

Once loaded, you can navigate to the web application using the target machine's browser ([http://172.17.0.3:80/](http://172.20.128.2/)):

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731136308031/64400b14-7248-44c5-bd9b-a5a42bef081c.png align="center")

Let’s now create a new account.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731136379511/c1d8f55f-b76c-4cfd-a330-3ab02b378721.png align="center")

And after we sign in we get our flag.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731136427197/5934d978-e097-43b9-9b08-0f2fdd2583bb.png align="center")

Flag: **THM{IaC.Pipelines.Can.Be.Fun}**

Congratulations! You have executed your very first IaC pipeline!