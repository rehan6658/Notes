---
title: "HackMyVM -  Runas"
seoTitle: "HackMyVM: Runas Walkthrough"
seoDescription: "Explore a Windows 7 hacking challenge, discovering user flag and root flag through web parameter exploitation in HackMyVM's "Runas" walkthrough"
datePublished: Wed Nov 20 2024 09:30:58 GMT+0000 (Coordinated Universal Time)
cuid: cm3poocro00020ald5zi21c4v
slug: hackmyvm-runas
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1732084508427/961c5d3a-70e6-42f8-95e3-c8c5851fd056.png
tags: hacking, vapt, web-exploitation, hackmyvm

---

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732084486317/e19c6302-6782-460e-be74-05849bf41d7b.png align="center")

Let’s Import our machine into the VM and boot it up.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732091229101/9b860f5c-8de9-4580-aaea-5fd6e109dd2e.png align="center")

We see that we have a Windows 7 machine with 2 users `Administrator` and `runas`. We don’t have any access to any user or something. So, moving back to our Kali machine.

First, let’s discover what our IP would be to start.

```bash
sudo netdiscover
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732091901913/2436e6b5-8df0-4108-adc8-7ea727721893.png align="center")

We see that `.144` is the entry point.

IP: **192.168.32.144**

Let’s start with nmap scan now.

```bash
nmap -sC -sV -o nmap 192.168.32.144
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732092126946/fd7d81c4-6b58-4c73-b52e-46400067d21e.png align="center")

We have lots of ports open so let’s begin with `port 80`.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732092190959/f9501493-0f26-4e2c-a4b4-ab4c6933c3a3.png align="center")

So we have an Index page in which we can see 2 files `index.php` and `styles.css`.

Checking the `index.php` page.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732092268962/60a56db2-4698-42ce-bbd7-4fa00a815693.png align="center")

We see some texts written, “There is no going back!”. And the interesting thing here is `?file=` parameter so let’s try to see if we can see something interesting.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732094257514/394ecffe-0576-4e02-b615-abea34596fef.png align="center")

We tried to list the `styles.css` file and we’re able to see its content.

let’s capture the request in Burp and try to abuse it.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732094460170/c53b4785-761b-42c2-b203-eaff1c6a54da.png align="center")

Let’s send it to the repeater tab.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732094640314/20f5c04a-7612-4781-ad25-b3b0e2b9925b.png align="center")

If we try to list our flag directly through our website we already know what the username is and it’s a Windows machine.

Mostly the flag is stored in the `C:/Users/<username>/Desktop/user.txt`. So let’s try this.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732094755059/c90dfc3c-77b8-4f8f-8c83-987d6da7d72d.png align="center")

And yeah, we got our 1st flag.

Flag: **HMV{User\_Flag\_Was\_A\_Bit\_Bitter}**

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732094820813/7a8237be-3a83-4a11-a2bb-ab97da986a8b.png align="center")

Now, let’s try to get the root flag as well by using the same method.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732094888223/2b242cf8-ce74-4574-9d42-2d89ffabf472.png align="center")

And we got our 2nd flag as well.

Flag: **HMV{Username\_Is\_My\_Hint}**

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732094937760/d190c4a4-f0bd-4b4a-bcc8-300514892fb9.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1732094980386/889a5a7f-6f43-41ed-964e-1c7d098cc976.png align="center")

And we’re done with this machine.