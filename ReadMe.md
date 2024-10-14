# ReadMe

## Introduction

本项目旨在帮助CTF初学者方便的去除常见花指令，可以在此基础上进行理解学习，有bug或者可以优化的地方欢迎和我联系交流(wx:y3049155267)
目前支持去除的花指令有这些，后续会持续更新

```
[*]pattern1:
//包括类似的jo jno,js jns等
		jz	label
		jnz	label
		db	_junkcode
label:	....
		....

[*]pattern2:
			CLC
			JNB 	label_1
			db 	_junkcode
label_1:


[*]pattern3:
        push ebx;
        xor ebx, ebx;
        jnz LABEL7;
        jz    LABEL8;
    LABEL7:
        _emit 0xC7;
    LABEL8:
        pop ebx;
        

[*]pattern4:
			call	label_1
			db		_junkcode
label_1:	        add	esp,4


[*]pattern5:
                       push    eax
			call	label_1
			db		_junkcode
label_1:	        pop	eax
                       pop     eax
                  

[*]pattern6:
			call	label_1
			db		_junkcode
label_1:	        add     dword ptr ss:[esp],6
                       ret
```



## Usage

### Install

将NoMoreFlower.py放入IDA的plugins目录后重启ida即可

### Use

安装好后点击Edit->Plugins->NoMoreFlower即可自动去除

![use](https://github.com/x1aon1ng/NoMoreFlower/blob/master/pic/use.png))
## 效果

### sample1

#### 去除前

![example_before](https://github.com/x1aon1ng/NoMoreFlower/blob/master/pic/example_before.png)

#### 去除后
![example_atfer](https://github.com/x1aon1ng/NoMoreFlower/blob/master/pic/example_atfer.png)

### sample2(MoeCTF2022 checkin_soup)

#### 去除前

![checkinsoup_before](https://github.com/x1aon1ng/NoMoreFlower/blob/master/pic/checkinsoup_before.png)

#### 去除后

![checkinsoup_after](https://github.com/x1aon1ng/NoMoreFlower/blob/master/pic/checkinsoup_after.png)
