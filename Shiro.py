# -*-coding:utf-8 -*-
from burp import IBurpExtender
from burp import IScannerCheck
from burp import IScanIssue
from burp import IMessageEditorTabFactory
from burp import IContextMenuFactory
class BurpExtender(IBurpExtender, IMessageEditorTabFactory, IContextMenuFactory, IScannerCheck):
    def registerExtenderCallbacks(self, callbacks):
        sys.stdout = callbacks.getStdout()
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        self._callbacks.setExtensionName("Used Shiro Check")

        # 注册扫描
        callbacks.registerScannerCheck(self)
        print '[+]-------------------------------------------[+]'
        print '[+]-----------author:RakJong---------------[+]'
        print '[+]Blog :https://www.cnblogs.com/2rsh0u[+]'
        print '[+]-------------------------------------------[+]'

    # 获取请求的url
    def get_request_url(self, protocol, reqHeaders):
        link = reqHeaders[0].split(' ')[1]
        host = reqHeaders[1].split(' ')[1]
        return protocol + '://' + host + link


    def get_request_info(self, request):
        analyzedIRequestInfo = self._helpers.analyzeRequest(request)  
        reqHeaders = analyzedIRequestInfo.getHeaders()  
        reqBodys = request[analyzedIRequestInfo.getBodyOffset():].tostring()
        reqMethod = analyzedIRequestInfo.getMethod() 
        reqParameters = analyzedIRequestInfo.getParameters()#参数
        return analyzedIRequestInfo, reqHeaders, reqBodys, reqMethod, reqParameters

    def get_response_info(self, response):
        analyzedIResponseInfo = self._helpers.analyzeRequest(response)  
        resHeaders = analyzedIResponseInfo.getHeaders() 
        resBodys = response[analyzedIResponseInfo.getBodyOffset():].tostring()  
        # resStatusCode = analyzedIResponseInfo.getStatusCode() 
    def get_server_info(self, httpService):
        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        ishttps = False
        if protocol == 'https':
            ishttps = True
        return host, port, protocol, ishttps
    # 获取请求的参数名、参数值、参数类型（get、post、cookie->用来构造参数时使用）
    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType
    def shiroCheck(self, reqUrl, request, httpService):
    
        # 构造参数
        parameterName = 'rememberMe'
        parameterValue = '123'
        parameterType = 2 #cookie
        newParameter = self._helpers.buildParameter(parameterName, parameterValue, parameterType)

        # 更新参数，并发送请求
        newRequest = self._helpers.updateParameter(request, newParameter)
        newAnalyzedRequest, newReqHeaders, newReqBodys, newReqMethod, newReqParameters = self.get_request_info(
            newRequest)
        # 新的响应
        newIHttpRequestResponse = self._callbacks.makeHttpRequest(httpService, newRequest) 
        if newIHttpRequestResponse == None:
            return False

        response = newIHttpRequestResponse.getResponse()        # 获取响应包
        if response == None:
            return False

        newResHeaders, newResBodys = self.get_response_info(response)

        for _ in newResHeaders:
            if 'rememberMe=deleteMe' in _:
                print '[+] Used Shiro: {} '.format(reqUrl)
                self.issues.append(CustomScanIssue(
                    newIHttpRequestResponse.getHttpService(),
                    self._helpers.analyzeRequest(newIHttpRequestResponse).getUrl(),
                    [newIHttpRequestResponse],
                    "Shiro",
                    "Used Shiro",
                    "High"))
                return True
    def start_run(self, baseRequestResponse):

        self.baseRequestResponse = baseRequestResponse

        # 获取请求包的数据
        request = self.baseRequestResponse.getRequest()
        analyzedRequest, reqHeaders, reqBodys, reqMethod, reqParameters = self.get_request_info(request)

        # 获取服务信息
        httpService = self.baseRequestResponse.getHttpService()
        host, port, protocol, ishttps = self.get_server_info(httpService)

        # 获取请求的url
        reqUrl = self.get_request_url(protocol, reqHeaders)
        #执行检测
        self.shiroCheck(reqUrl, request, httpService)
    #被动扫描
    def doPassiveScan(self, baseRequestResponse):
        '''
        :param baseRequestResponse: IHttpRequestResponse
        :return:
        '''
        self.issues = []
        self.start_run(baseRequestResponse)
        return self.issues


    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        '''
        相同的数据包，只报告一份报告
        :param existingIssue:
        :param newIssue:
        :return:
        '''

        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1

        return 0

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, severity):
        '''
        :param httpService: HTTP服务
        :param url: 漏洞url
        :param httpMessages: HTTP消息
        :param name: 漏洞名
        :param detail: 漏洞细节
        :param severity: 漏洞等级
        '''
        self._httpService = httpService
        self._url = url
        self._httpMessages = httpMessages
        self._name = name
        self._detail = detail
        self._severity = severity

    def getUrl(self):
        return self._url

    def getIssueName(self):
        return self._name

    def getIssueType(self):
        return 0

    def getSeverity(self):
        return self._severity

    def getConfidence(self):
        return "Certain"

    def getIssueBackground(self):
        pass

    def getRemediationBackground(self):
        pass

    def getIssueDetail(self):
        return self._detail

    def getRemediationDetail(self):
        pass

    def getHttpMessages(self):
        return self._httpMessages

    def getHttpService(self):
        return self._httpService
