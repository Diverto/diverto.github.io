---
layout: post
title: "Human in cybersecurity: Teach a man to phish..."
date: 2024-10-02
author: svan
categories: [phishing, e-mail, human]
category: phishing, e-mail, human, social engineering
color: red
tags: [phishing, e-mail, human, social engineering]
otherLanguages:
- locale: hr
  path: /hr/blog/2024-10-02-teach-a-man-to-phish
---

Social engineering attacks, especially *phishing* attacks, have come a
long way from [simple Nigerian prince mails](https://en.wikipedia.org/wiki/Advance-fee_scam) although, this tried and
widespread tactic still [rakes a lot of money](https://www.cnbc.com/2019/04/18/nigerian-prince-scams-still-rake-in-over-700000-dollars-a-year.html) using the most basic of all human drives, greed.

These days, we are more likely to see advanced forms of *phishing*
attacks that target a specific person or group. Examples of such mail
are numerous, and all it takes to find one is to open your own email
inbox.

Fast development of AI made *phishing* easier than ever with plethora of
tools that aid the attackers with omitting telltale signs of old; wonky
translations and grammatic or/and spelling errors.

### Tackling the Phish
To successfully combat advanced *phishing* mails, most organizations
rely on establishing education programs and conducting email phishing
tests as often as possible. However, as some examples show[^1], spamming
the employees with daily *phishing* mails is not only counterproductive,
but also dangerous for organizations especially if failing the
*phishing* test results with sanctions and punishment.

As Frank Herbert wrote, "Fear is the mind-killer", and most people tend
to lose themselves in a constant state of anxiety about some unknown
attacker lurking from the shadows, be it a malicious hacker or a member
of the IT security team trying to prove that nobody is safe. That's why
most *phishing* tests tend to be a double-edged sword, a mechanism more
likely to cause distrust towards the security team and apathy among
employees if not used correctly than part of user centric education
program designed to give the employee the tools needed to take active
stance in defense of organization.

### Teach a Man to Phish...
Well then, how to phish? With precision and with the employee in mind,
using different *phishing* templates that are more or less difficult to
recognize. And to adequately assess the "hardness" of *phishing* mail,
we need a methodology that can cover most of the scenarios we use in
testing and that allows us to measure the evolution of employee's
resilience.

In order to rate the mails we use to test our employees, we can use the
NIST Phish Scale[^2], a method that allows us to easily measure the
detection difficulty of a *phishing* mail.

The Scale is biaxial, with one axis providing us with *"A scoring system
for observable characteristics of the phishing mail itself",* and other
with "*A scoring system for alignment of the phishing email premise with
the respect to a target audience"*[^3]. In short, one axis tells us "How
dirty the *phishing* mail is?", while other tells "How appropriate the
mail is?".

To assess how "dirty" the *phishing* is, NIST provided us a set of email
cues that are distributed into five big categories[^4]:

1. *Errors -- relating to spelling and grammar errors and
   inconsistencies contained in the message;*

2. *Technical indicators -- pertaining to email addresses, hyperlinks
   and attachments;*

3. *Visual presentation indicators -- relating to branding, logos,
   design and formatting;*

4. *Language and content -- such as a generic greeting and lack of
   signer details, use of time pressure and threatening language; and*

5. *Common tactics -- use of humanitarian appeals, "too good to be
   true" offers, time-limited offers, poses as a friend, colleague, or
   authority figure, and so on.*

After we used the afore mentioned categories of cues to analyze the
"dirtiness" of *phishing* mail, it remains to be seen how aligned the
premise of the *phishing* mail is to the context of the organization we
are testing. Phish Scale states that:

> *Premise alignment is a measure of how closely an email matches the
> work roles or responsibilities of an email's recipient or
> organization. The stronger an email's premise alignment, the more
> difficult it is to detect as a phish. Inversely, the weaker an email's
> premise alignment, the easier it is to detect as a phish.*

Using this method, we can finally, and with high precision, determine
the "difficulty" of specific *phishing* mail.

But that's only half of the picture... To have a clear picture of an
organization's resilience to phishing attacks, we need to correlate how
user react on phishing emails.

### Downstream or Upstream?
To do that, we need to categorize how employees react when challenged
with *phishing* mail in one of the four categories (from better to
worse):

1. *Didn't click and reported*

2. *Clicked and reported*

3. *Didn't click and didn't report*

4. *Clicked and didn't record*

Let's say that we have 4 different employees that are being tested, Amy,
John, Doug, and Winston.

Winston receives the *phishing* mail, opens the included link, and
doesn't report anything to the security team. This is the least
favorable behavior because it leaves our organization possibly
penetrated and our security team blind.

John on the other hand, receives the *phishing* mail, sees it's a fake,
deletes it from his inbox and carries on with his daily activities
without notifying the security team. This still isn't good enough.
Although John can recognize *phishing* mail, the security team is still
blind. Winston clicked, the organization is possibly compromised, and a
report from John could have helped the security team to respond
accordingly.

Doug, distracted from all the work and deadlines, clicked the link in
the *phishing* mail. But Doug then recognized that the URL address was
wrong and that the landing site was fake. He recognizes that he erred
and reports his actions to the security team. This is good for several
reasons. Firstly, Doug trusts the security team enough to admit he did
wrong. Secondly, the security team now knows that the organization is a
target of a *phishing* campaign and, based on that information, they can
block the sender, pull all the similar emails from employees' inboxes,
issue a warning, or even force all the employees to change their
passwords.

Finally, we have Amy. She didn't click and she reported the *phishing*
mail to the security team. She recognized the *phishing* mail and took
an active stance in defending the organization. This is the most
favorable course of action that an employee can take when faced with
*phishing* mail.

### The Resilience of the School
Once we categorized the behavior of our employees into four said
categories, we take the worst and the best results and calculate the
resilience score of the organization:

![Picture1.png](/images/2024-10-02-teach-a-man-to-phish/capture1.png)

Let's analyze a specific case. In the graph below we can see the results
that Organization A scored on *phishing* test:

![Picture2.png](/images/2024-10-02-teach-a-man-to-phish/capture2.png)

In short, resilience score for this specific organization is:

![Picture3.png](/images/2024-10-02-teach-a-man-to-phish/capture3.png)

Ok, now we have a number that is derived from click and report rates.
How do we determine if an organization is resilient or not? We use the
thresholds.

For instance, in the context of the tests that we conducted[^5], we
defined the following thresholds:

![Picture4.png](/images/2024-10-02-teach-a-man-to-phish/capture4.png)

So, based on the thresholds we defined, Organization A from our previous
example is not resilient enough and needs to work on raising the
awareness of employees.

### Wild Blue Ponder
However, now that we have all this data, a new challenge arises! How to
compare results from different campaigns? How to keep track of
improvement or deterioration of our employee's resilience to phishing
attack?

We introduce ponders that help us in comparing the campaigns of
different difficulty. If this sounds a little bit complex, you are
right. It takes a long road to go from a Nigerian prince to resilience
score ponders.

Let's go back to the beginning and illustrate how to get the most
complete picture of organization resilience and how to compare it with
other results:

1. Determine the difficulty of *phishing* mail

2. Send the mail to targets

3. Gather the info about reports

4. Categorize the behavior into one of four categories

5. Calculate the resilience score

6. Ponder the resilience score based on the difficulty of phishing mail

Based on our experience, the ponders are:

- Least difficult mail = 1

- Moderately difficult mail = 2,5

- Very difficult mail = 4

So, after we multiply the resilience score with appropriate ponder, we
can track it through multiple campaigns which gives us ability to
reevaluate our awareness raising educations and our employee's
readiness.

Here's drill down a comparison of results:

![Picture5.png](/images/2024-10-02-teach-a-man-to-phish/capture5.png)

### Not the only Phish in the Sea
The *phishing* story isn't all about the click, but reporting, about
education, and about continuous testing that strives to empower the
employees, not to sanction them. In the end, it's about building the
relationship of trust and mutual respect between employees and the
security team.

### References

[^1]: https://www.nwcrc.co.uk/post/simulated-phishing-exercise-guide

[^2]: Dawkins, S., Jacobs, J. (2023) NIST Phish Scale User Guide.
    (National Institute of Standards and Technology, Gaithersburg, MD),
    NIST Series TN 2276. https://doi.org/10.6028/NIST.TN.2276

[^3]: Ibid.

[^4]: Ibid.

[^5]: Why in context? Because Proofpoint suggests that a good resilience
    score is 14 or more. It's not derived using completely the same
    metrics, but it's in line with the approach we described in detail.
    Having 70% report rate and 5% click rate is still very far from even
    the most resilient organization in our scope. However, we always
    tend to follow trends and adjust accordingly and, in a few years,
    maybe our thresholds will be in line with what Proofpoint suggests.

    <https://www.proofpoint.com/us/blog/email-and-cloud-threats/reporting-phishing-simulations-essential-metric-measure-phishing>
