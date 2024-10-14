# ReadMe

## Introduction

本项目旨在帮助CTF初学者方便的去除常见花指令，可以在此基础上进行修改学习

目前支持去除的花指令有

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

## ![use](https://github.com/x1aon1ng/NoMoreFlower/blob/master/pic/use.png))效果

### sample1

#### 去除前

![example_before](E:\xhs实习\花指令学习\NoMoreFlower\pic\example_before.png)

#### 去除后![example_atfer](E:\xhs实习\花指令学习\NoMoreFlower\pic\example_atfer.png)

### sample2(MoeCTF2022 checkin_soup)

#### 去除前

![checkinsoup_before](E:\xhs实习\花指令学习\NoMoreFlower\pic\checkinsoup_before.png)

#### 去除后

![checkinsoup_after](E:\xhs实习\花指令学习\NoMoreFlower\pic\checkinsoup_after.png)
