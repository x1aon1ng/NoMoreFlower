# ReadMe

## Introduction

**TODO**：

- [ ] 自定义花指令批量去除
- [ ] 常见花指令去除误杀bug fix

本项目旨在帮助CTF初学者方便的去除常见花指令，可以在此基础上进行理解学习，有bug或者可以优化的地方欢迎和我联系交流
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

### How to use

安装好后点击Edit->Plugins->NoMoreFlower,然后Edit->Patch programs->apply patches to，最后重新打开ida，让ida重新自动分析即可

![use](https://github.com/x1aon1ng/NoMoreFlower/blob/master/pic/use.png))
## 效果

### sample1

#### Before

![example_before](https://github.com/x1aon1ng/NoMoreFlower/blob/master/pic/example_before.png)

#### After
![example_atfer](https://github.com/x1aon1ng/NoMoreFlower/blob/master/pic/example_atfer.png)

### sample2(MoeCTF2022 checkin_soup)

#### Before

![checkinsoup_before](https://github.com/x1aon1ng/NoMoreFlower/blob/master/pic/checkinsoup_before.png)

#### After

![checkinsoup_after](https://github.com/x1aon1ng/NoMoreFlower/blob/master/pic/checkinsoup_after.png)
