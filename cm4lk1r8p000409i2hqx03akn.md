---
title: "Understanding CAN Bus and performing Replay Attack"
seoTitle: "CAN Bus Guide: Replay Attack Explained"
seoDescription: "Learn about CAN Bus vehicle networks and conduct a basic replay attack using our interactive car hacking guide"
datePublished: Thu Dec 12 2024 16:50:03 GMT+0000 (Coordinated Universal Time)
cuid: cm4lk1r8p000409i2hqx03akn
slug: understanding-can-bus-and-performing-replay-attack
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1734022079291/4a2f58fa-29ca-4252-b6c4-137960a0466a.jpeg
tags: hacking, infosec-cjbi6apo9015yaywu2micx2eo, cybersecurity-1, ethicalhacking, car-hacking, can-bus, replay-attack

---

Getting started with Car Hacking, with an introduction to CAN Bus and hands-on with a basic replay attack.

# Objective

Understanding CAN Bus vehicle communication network and getting hands-on with a basic replay attack in the network.

# Theory

**Introduction to CAN Bus**:

The Controller Area Network (CAN) Bus serves as a communication infrastructure within vehicles that interconnects sensors and controllers(Electronic Control Unit - ECU), facilitating the exchange of data. Air Conditioner, ABS, and Window control are some of the ECUs in cars.

![](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/carhack/newproc/4c19037234afff5d70cc478955614a431df85e2238e1a29ce2ab765c4f5cfd94.png align="left")

[Simplified CAN Bus topology](https://securityqueens.co.uk/hax-and-furious-an-introduction-to-can-bus-hacking-with-icsim/)

For each device, the data in a frame is transmitted serially in the network, but in such a way that if more than one device transmits at the same time, the highest priority device can continue while the others back off. Frames are received by all devices, including by the transmitting device. This data is local to a vehicle.

**In this lab exercise, we will try to gain familiarity with this data traffic**

More In-Depth on CAN Bus can be checked out here- [CAN Bus Wikipedia](https://en.wikipedia.org/wiki/CAN_bus)

The OBD-II (On-board diagnostics 2) port on vehicles acts as the access point for communication on the CAN Bus. Hardware tools can be connected directly to it to be able to retrieve data which can then be parsed or analyzed.

![](https://assets-ine-com.s3.us-east-1.amazonaws.com/content/labs/cyber/carhack/newproc/d0f929ef238b62cade240476013c096022555380a5a287d06c2b2a57162d081f.png align="left")

# Lab Environment

In this lab environment, you will get access to the GUI of the attacker's Ubuntu Machine with a Car Dashboard Simulation Web UI, a virtual CAN network interface "vcan0" and a "can-utils" tool. The Car Dashboard Simulator can be accessed at

```bash
http://demo.ine.local
```

# Tools

The tools used in the lab:

* Car Dashboard Simulator: Observing actions as dictated by the data packets.
    
* can-utils: Linux utilities for interfacing with Controller Area Network (CAN) devices, facilitating monitoring and control in automotive and embedded systems.
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734019991079/abe4d31d-34ae-4739-bf9e-14cb2dd79f2d.png align="center")

Now here, we have our web UI simulating a car dashboard.

We can see that there are 3 actions which can be performed

1. Toggling turn signals
    
2. Locking/Unlocking doors.
    
3. Updating the speedometer.
    

Let’s try out each button and observe it’s actions before we start the testing.

Clicking on the Left indicator button changes the state of light for a fraction of a second. The color changes to orange. Now let’s click longer for it to register the signal change.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734020200708/9f0064e3-daa5-47fe-8e8f-45c16563e0ed.png align="center")

Now looking at the door we can see that it’s initially locked indicated by “red”. let’s try to unlock it by using the door unlock button.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734020374496/3fd0437d-9009-43f1-9770-4fedaf4c2a1a.png align="center")

Clicking the Door 1 Unlock button we can see that the light has changed to green which indicates that the door is now unlocked.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734020444991/25b381ef-c8a7-48ff-8a90-218e64d666a5.png align="center")

Clicking the Door 1 lock will again change the color to red.

Now the last button is the Accelerate button. If we click on it the speedometer changes and the speed of the car increases.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734020570090/60d1724a-3bde-4def-9d37-619ca9ea7d96.png align="center")

If we release our mouse the speed starts decreasing. All these actions generate data packets in the CAN Bus. Now that we’re done with trying out the features let’s start with the testing part.

Let’s first check if the system is detecting the virtual CAN interface.

```bash
ifconfig vcan0
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734020765116/0816795f-239f-4a85-8996-b685099c1ddf.png align="center")

Yes, it’s running perfectly. Let’s now use `candump` from “[can-utils](https://github.com/linux-can/can-utils)”.

```bash
candump vcan0
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734020919312/976e9e80-1374-47cf-8370-d9562ca43a97.png align="center")

So, It shows us the packets currently flowing in the network.

This displays a random CAN traffic noise currently in the network. In a real car network there would be way more number of data packets.

> A sample data frame has the following structure

```bash
vcan0  164   [8]  00 00 C0 1A A8 00 00 22
___
vcan0: The virtual CAN interface
164: The arbitration ID(in hexadecimal). Used by network members to identify, whether the message is intended for it or not.
[8]: The message size
00 00 C0 1A A8 00 00 22: The message data (limited to 8 bytes)
```

Every ECU (Electronic control unit) responds according to the arbitration ID which is used to identify if the message is for it or not. **The lower the arbitration ID, the higher the priority of the message in case multiple ECUs start sending messages at the same time**. Once identified the action is undertaken by ECU from the message data.

We can also see this data inside wireshark by selecting the `vcan0` interface.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734021152399/e8fb0056-968c-40a4-a1bb-19e40496c276.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734021173296/26be66da-2311-44e9-bcc4-31259fc0bda8.png align="center")

Now let’s try to log our actions using these data packets.

```bash
candump -l vcan0
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734021250894/aee8141c-1316-451f-b21f-3563747f26b7.png align="center")

This will start to record and log data packets from this point in time until it’s stopped.

Now, on the simulator window let’s perform some random actions and stop the logger to store the corresponding data packets of our actions.

1. "Left Indicator" click once
    
2. "Door 1 Unlock" click once
    
3. "Door 1 Lock" click once
    
4. "Accelerate" click and hold for a while and release the click.
    

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734021465073/3211b27f-e21b-436c-a874-aa044bf77960.png align="center")

Now let’s stop the logger and it will save our log file.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734021508766/0cbb851b-7ffd-4444-a3c9-7ee32223c6b5.png align="center")

So, here we have our log file `candump-2024-12-12_163402.log`. let’s read the content of it.

```bash
cat candump-2024-12-12_163402.log
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734021611911/d36494d3-64aa-49d4-ba27-943977d301a8.png align="center")

The log file has all the packets stored along with the noise traffic plus the packets generated from our actions.

Now, Using the packets we will perform a basic replay attack.

```bash
canplayer -I candump-2024-12-12_163402.log
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1734021892124/5df15344-574b-4b68-97b5-326e7da05d31.png align="center")

We can see that the same set of observations are being repeated on the UI. The data packets are sent in the network and corresponding actions are replayed.