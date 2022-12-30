---
layout: post
title: Introduction to hybrid SOC model
date: 2022-12-28
author: Ivan
categories: [SOC, SIEM]
category: SOC, SIEM
color: green
tags: [SOC, SIEM ]
otherLanguages:
- locale: hr
  path: /hr/blog/hybrid-soc
---
Let’s think of situation where your organization have too few people who work in security or they lack skills to perform advanced analyses usually assigned to Tier 2/3. For example, you have a couple of security analysts who are more than able to perform triage and maybe handle less complicated incidents. Now that’s when hybrid SOC model comes in.

If you are reading this page, chances are you already know what Security Operations Centre, or SOC, is. Nevertheless, let’s take a moment to review the basics.

SOC is a synergy of processes, people and technology that enables you to detect, analyze and respond to events that point to potential security incident. How is it different than SIEM you wonder? Well, SIEM is an integral part of every SOC. Without it, security teams would have extremely hard time detecting potential threats. A great piece of technology for sure, but SIEM itself will not make decisions, communicate key information to stakeholders or respond to possible threats. And that is where other 2 parts of the equation, people and processes, come in.

Once you put it all together, it looks something like this:

![Basic SOC model](/images/2022-12-28-hybrid-soc/hsoc1.png)

In essence, you’ll have your logs collected, enriched, and organized. Some smart people will have those logs monitored and analyzed for indicators of potential security threats. Once they decide there is a threat looming, they’ll communicate right information to right people and participate in efforts to contain and eliminate that threat.

# So, what’s the story with different Tiers?

People who work with information within SOC environment are assigned to different Tiers and have different tasks. For example, people who belong to Tier 1 will be tasked with routine detection and analysis operations and are generally known as first responders. Tier 2 are skilled specialists who will perform further investigations through correlations and information gathered by threat intelligence. Tier 3 people are most skilled specialists who perform tasks such as threat hunting, malware analysis and forensics.

So why not just let Tier 3 specialists handle everything? Because SOC tiering is a method to put your limited resources to a more efficient use.

It is likely that your organization will get hundreds, if not thousands, messages from SIEM. If you task your Tier 2/3 specialists to analyze and triage all those messages and alerts, it’s likely they’ll get overwhelmed and lose time and energy that could otherwise be used to perform more advanced analysis. That is not what you’ll want to do – you’ll want them to use their skills to handle more complicated cases.

# But what if security manpower resources in my organization are limited?

Now that’s when hybrid SOC model comes in.

Let’s think of situation where your organization have too few people who work in security or they lack skills to perform advanced analyses usually assigned to Tier 2/3. For example, you have a couple of security analysts who are more than able to perform triage and maybe handle less complicated incidents. And that is probably good enough for, let’s say, 80% of security events that your organization will face. But what to do with other 20%? It might not be exactly cost-effective to hire expensive specialists who will sit idle most of their time and wait for something big to happen.

There is a better alternative. Keep your people doing Tier 1 tasks and get outside help to handle the rest. You’ll get expert support when you need it, get handling of more complicated security incidents covered and save some money in the process. Considering all of this, hybrid SOC model would look a bit differently than seen on previous picture:

![Hybrid SOC model](/images/2022-12-28-hybrid-soc/hsoc2.png)

# What are the success factors for hybrid SOC model?

First and foremost, **communication**. All Tiers, all well as all relevant stakeholders, should always exchange key information in a timely manner. Tiers 2/3 will do little good if they don’t get all the facts about the potential threat.

Other is choice of **appropriate external partner**. It’s not only that their people require proper skills to perform advanced analyses – patience, communication skills and availability are all required to work with your people towards common goals.

Also, worth mentioning are two things that all SOC models have in common – get your technologies and processes right. All aspects of your SOC should be aligned to get best results.

# Experience with hybrid SOC model

So far, our experience running hybrid SOCs shows that hybrid SOCs are possible in companies of various industries and sizes. The hybrid SOC model can be a cost-effective solution for organizations that do not have the resources or expertise to fully manage their own security operations.
Most important part is that you have experienced people that can help to shorten implementation time and can optimize time needed to setup and operate hybrid SOC. That way you can get the best results out of your hybrid SOC model.


