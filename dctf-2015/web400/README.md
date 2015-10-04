# Web400 Challenge

So basically the main goal of this challenge was to pwn the server and get the flag..

We were presented by this website:

![alt Web400 Index] (https://i.imgur.com/E1WTkaA.png)

Nothing special at first glance, however if we look closely we can see that the images are loaded from another page.
The url was http://10.13.37.5/?id=1&usr=1 and immediately tried some SQL Injection tricks, but I got this error:

![alt Web400 Int Error] (https://i.imgur.com/yCv6sJ6.png)

This was strange, can I bypass this check? or there is another way to win this?

After some tries I noticed that if I change the 'id' parameter for example to '2' (non existing id) I get a corrupted image as an output. I downloaded the image and opend it with an hex editor and strangely I saw this error "cat: images/2_6.jpg: No such file or directory".

As you can see the php script tried to read the image, however it used 'system' function to do that, also you can see that my controled input 'id' I changed appears in the error. This is great, I can control the input that goes straight to the 'system' function!

Hm.. but wait, isn't the id input is filtered to allow only integer inputs? There are two ways they might have used to check this:

1. Regex Check
2. is_numeric function

#### Here comes the php magic :)

The 'is_numeric' function documentation:

> Finds whether the given variable is numeric. Numeric strings consist of optional sign, any number of digits, optional decimal part and optional exponential part. Thus +0123.45e6 is a valid numeric value. Hexadecimal (e.g. 0xf4c3b00c), Binary (e.g. 0b10100111001), Octal (e.g. 0777) notation is not allowed.

The hexadecimal notation looked interesting, and I tired this input: http://10.13.37.5/?id=0x61626364&usr=1. The error message I got was: "cat images/abcd_6.jpg: No such file or directory", So this worked!

After some fixes I managed to run arbitrary commands on the server with this method:

```bash
$(`uname -a > /tmp/tmp123.tmp`) || cat /tmp/tmp123.tmp || echo 
```

#### The fun part! where is the flag?
The web server was apache and the linux disto was ubuntu, so the default web root path must be: "/var/www/html", I tried to list the files there and the website was right there!

My final command:

```bash
$(`cat 6e8218531e0580b6754b3e3be5252873.txt > /tmp/tmp123.tmp`) || cat /tmp/tmp123.tmp || echo 
```

URL: http://10.13.37.5/?id=0x2428606361742036653832313835333165303538306236373534623365336265353235323837332e747874203e202f746d702f746d703132332e746d706029207c7c20636174202f746d702f746d703132332e746d70207c7c206563686f20&usr=1

Flag: DCTF{19b1f9f19688da85ec52a735c8da0dd3}
