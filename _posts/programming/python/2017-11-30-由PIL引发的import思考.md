---
layout: post
title: "由PIL引发的import思考"
categories: programming python 
tags: python import PIL
---



一直对python的import机制不是特别理解，直到最近又使用pillow，因为有段时间没用pillow了，所以没有按照官方docs里的方式，而是直接import了：

```python
import PIL
PIL.Image 	#error
'''
Traceback (most recent call last):
  File "/tmp/piltest.py", line 2, in <module>
    im=PIL.Image.open("one.jpg")
AttributeError: module 'PIL' has no attribute 'Image'
'''
```



一开始以为是pillow的安装有问题，将`/usr/lib/`下的删除后，在`/home`下又装了一遍，发现还是不行。

查看`__init__.py`发现其几乎是个空文件，只定义了几个常量，没有其他内容，所以`PIL.Image`必然不存在，因为import不会自动导入`.../PIL/*.py`文件。



对python的import的机制总结如下：

- `import PIL`和`from PIL import *` 效果（基本）一样，但是只会导入`__init__.py`文件中import的对象，[不会自动递归import子模块][1]。
- `from PIL import Image`导入指定的`.../PIL/Image.py`（第一种方式不会自动导入子模块）。
- `from PIL import VERSION`导入指定的`__init__.py`中的`VERSION`对象（第一种方式会自动导入）。



[1]: https://stackoverflow.com/questions/11911480/python-pil-has-no-attribute-image

