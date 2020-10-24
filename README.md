# BurpPlugin
判断是否使用shiro的burp插件，插件存在的缺陷是未判断burp请求中的js/css或者图片等链接而存在大量告警，待优化！
编写思路：获取经过burp porxy的所有请求和响应并分析-->构造cookie rememberMe参数重新发送-->获取新的请求和响应，存在rememberMe=deleteme即显示在被动扫描模块
参考：https://xz.aliyun.com/t/7065
     https://gv7.me/articles/2017/classification-of-burp-apis/
加载插件：
![Image text](https://github.com/rakjong/BurpPlugin/blob/main/add.jpg)

被动检测效果：
![Image text](https://github.com/rakjong/BurpPlugin/blob/main/plugin.jpg)

