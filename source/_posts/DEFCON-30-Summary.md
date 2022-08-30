---
title: DEFCON 30 Summary
date: 2022-08-15 12:51:00
category: Experience
tags:
    - DEFCON
---

## Best Gift

I am honored that my team `r3kapig` provides this precious opportunity to participate on-site in DEF CON CTF in Las Vegas! For a beginner who has just learned security for about a year, this is undoubtedly an eye-opening experience. 

My birthday is around August, so I consider it my best birthday gift.  

![badge](assets/badge.jpg)

![CP-r3kapig](assets/CP-r3kapig.jpg)

## Day1: A Rough Start

On the first day, NI(Nautilus Institute) released three AWD challenges, `router_pi`, `web4_factory`, and  `perplexity`. I mainly focus on the `router_pi` challenge because it is a relatively easy one. 

The http service is buggy everywhere, almost like the [Tenda RouterTenda AC18 AC1900 Router
](https://thomasonzhao.cn/2022/08/05/Tenda-AC18-AC1900-Router/). One obvious vulnerability is the `ping` command injection. Thank the weak password. I quickly constructed a Burp Suite Intruder payload to attack other teams' vulnbox. 

![burp-exploit](assets/burp-exploit.jpg)

Since it is just at the beginning of the game, as usual, NI's infrastructure bug results that some teams being unable to upload their patch. Only two teams patch their program to defend against this. This almost became the main source of the flag. Even close to the end of the day, we can still grab 3~4 flags each round.  

However, at the end of the first day, NI announced that today's challenges would not show up again in the captain's meeting. So other teammates in China cannot prepare for the game during their day. 

**Live CTF**

But good news is: God n132 wins the first round of live ctf with opponent from `water paddler`!

![n132-yyds](assets/n132-yyds.jpg)

## Day2: Getting Better and Harder

In second day, new challenges are released: `mambo_server`, `nivisor_v1`, `nivisor_v2`, `corewar-n1` (KOH), and `corewar-n2`. I turn to focus on the operation and maintenance of EXP scripts and the vulnbox. We found that some team seemed to install a persistent trojan on our vulnbox yesterday. Cause us to lose points, and no one cares about the vulnbox machine. I wrote a simple bash script to monitor the processes and `/tmp` directory. 

Also, since NI's scoreboard can only show the current score at the current round (tick), I wrote a simple scorebot by python script to grab the information and sync it to the team message. Not perfect, though. It only shows the score changes compare to the last round and has no graph view. 

![scorebot](assets/scorebot.png)

I also decided to write an AWD exp platform rather than just tmux and run it in my WSL. Probably write it in the future to prepare the next AWD-like ctfs. But at the current stage, the flags are more important than the platform. 

The overall situation isn't good compared to the first day. The challenges are not that simple, and we lack people to reverse and exploit the binaries. Luckily, NI decides to release the source file of the top teams in KOH. We can copy their code to make denfence. And then something funny happens. Everyone wins the KOH (Just a joke, the horizontal row represents the team's status as host (host and guest will compete for their code) in the core, so there still have losses, just not shown on the board). Everyone wins the same as no one wins. 

![win-win](assets/win-win.jpg)

**Live CTF**

Again in live ctf: God 2019 wins the second round of live ctf! We are now in the top 4 on the live ctf rank. 

![2019-yyds](assets/2019-yyds.jpg)

## Day3: End? Never Ends at 196!

On the last day of the game, Our main force found a new vulnerability that could exploit almost all teams in both `nivisor_v1 & nivisor_v2` on their day. Just waiting for NI to open the infrastructure and debug the service. 

However, it took longer than it was expected, and the game just ended 1 hour earlier than it was supposed to because of the infrastructure issue. Not only us but also other hackers get annoyed by this. So we have the following memes:

![scoreboard-rule-meme](assets/scoreboard-rules.png)

After the end of the whole game, we asked Fish about the reason, he said that:
> Each time when a service get down (not pwned, just broken), we will pause the scoreboard and wait the service to reinitialize itself otherwise the game will be unfair. But seems we choose the wrong language to write the challenge. Python's memory manipulation is too bad. So a team is constantly been attacked and we can't fix this issue. We have not choice but to end the game.

**Live CTF**

Sadly, God 2019 lose in the live ctf against `perfect root`. Not because the challenge is so hard that he didn't know how to do, but because the challenge is too simple, he just not fast enough. It's not his fault, we all proud of him. 2019&n132 YYDS!

Here is he overall scoreboard provided by team `MMM`.

![scoreboard-by-mmm](assets/scoreboard-by-mmm.png)

##  Not Just Hacking

**Gordon Ramsay's Fish and chips!** 

It's not very tasty though, not recommend. But still nice thing to try "classic English food" in American. 

![fish-and-chips](assets/fish-and-chips.jpg)

**Hash!** 

A very good brunch resterant! It's just downstairs from the Linq hotel. Convenient and cheap, recommend. 

![hash](assets/hash.jpg)

**Beautiful Water Fountain!** 

Although not as good as the fountain in Shenzhen Sea World, hahaha. 

![water-fountain](assets/water-fountain.jpg)

**People**

Luckily, team `Shellphish` is at the table next to us. I met Professor Yan and successfully took photo with him. He is the founder of [pwn.college](https://pwn.college/) as well as one of the main organizers of DEF CON CTF in the past few years (2018~2021), known as OOO-[the Order of the Overflow](https://oooverflow.io/)

![photo-with-yan](assets/photo-with-yan.jpg)

He is a really nice guy. Owing to time constraints, I only have a short conversation with him:

> "Yoo\~ You just finished pwncollege and now you are in DEFCON! Which team are you in?"
> "r3kapig!"
> "Oh r3kapig\~ r3kapig will win this game, they will be the champion!"
> "Haha, not that easy as to earn a blue belt\~"
> "Haha, for sure\~"

Also, meet a lot of friends and get familiar with other team members, 2019, n132, 20, 1ph0n, saccharide, oroggs.

![we-are-r3kapig](assets/we-are-r3kapig.jpg)
