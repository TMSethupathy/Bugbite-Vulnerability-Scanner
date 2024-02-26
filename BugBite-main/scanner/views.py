from django.shortcuts import render,redirect,get_object_or_404
from .models import Scan,TargetDetails,OSInformation,ServiceDetails,ScanResult
from .forms import ScanForm

from django.http import HttpResponse
from .utils import render_to_pdf
import requests
from urllib.parse import urljoin
from bs4 import BeautifulSoup as bs
from .scripts import sqlInjectionErrorFunction,lfiErrorFunction,xssErrorFunction,directoryErrorFunction,clickJackingErrorFunction,robotTxtFunction,siteMapXmlFunction,autoCompleteCheckerFunction

from .nmap_scan import nmap_scan,os_scan
import socket
from urllib.parse import urlparse
import datetime
from django.template.loader import get_template
from xhtml2pdf import pisa
import json
url_links = None
url_imgs = None
originalUrl = None

sqliReport = None
lfiReport = None
xssReport = None
csrfReport = None
urlRedirectionReport = None
iframeReport = None
autoCompleteReport = None
directoryReport = None
robotsReport = None
siteMapXmlReport = None
httpReport = None

os_report=None
results_report=None
website_report=None

def view_project(request):
    projects=Scan.objects.all()
    return render(request, "view_project.html",{'projects':projects})
    
def view_details(request, pk):
    scan = get_object_or_404(Scan, pk=pk)
    target_details = scan.targetdetails_set.first()
    service_details = target_details.servicedetails_set.all()
    os_information = target_details.osinformation_set.all()
    
    scan_results = ScanResult.objects.filter(target=target_details)
    scan_result_dict = {}
    for scan_result in scan_results:
        if scan_result.scan_type in scan_result_dict:
            scan_result_dict[scan_result.scan_type].append(scan_result)
        else:
            scan_result_dict[scan_result.scan_type] = [scan_result]

    return render(request, "view_details.html", {'scan': scan,'target_details':target_details,'service_details':service_details,'os_information':os_information, 'scan_result_dict': scan_result_dict})

def delete_project(request, project_id):
    project = get_object_or_404(Scan, id=project_id)
    project.delete()
    return redirect('project')
def export_pdf(request, pk):
    template_path = 'pdf.html'
    scan = get_object_or_404(Scan, pk=pk)
    target_details = scan.targetdetails_set.first()
    service_details = target_details.servicedetails_set.all()
    os_information = target_details.osinformation_set.all()
    #scan_results=target_details.scanresult_set.all()
    scan_results = ScanResult.objects.filter(target=target_details)
    scan_result_dict = {}
    for scan_result in scan_results:
        if scan_result.scan_type in scan_result_dict:
            scan_result_dict[scan_result.scan_type].append(scan_result)
        else:
            scan_result_dict[scan_result.scan_type] = [scan_result]

    context = {
        'details': scan,
        'target_details': target_details,
        'service_details': service_details,
        'os_information': os_information,
        'scan_result_dict':scan_result_dict
    }
    response = HttpResponse(content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{scan.projectname}.pdf"'

    template = get_template(template_path)
    html = template.render(context)

    pisa_status = pisa.CreatePDF(html, dest=response)
    if pisa_status.err:
        return HttpResponse('Error Occurred while Generating PDF')

    return response


def GeneratePdf(request):
    try:
        directory_URL = directoryReport()
        robots_URL = robotsReport()
        siteMapXml_URL = siteMapXmlReport()
        http_URL = httpReport()
        sqli_URL = sqliReport()
        lfi_URL = lfiReport()
        xss_URL = xssReport()
        csrf_URL = csrfReport()
        urlRedirection_URL = urlRedirectionReport()
        iframe_URL = iframeReport()
        autoComplete_URL = autoCompleteReport()

        scan_results=results_report()
        os_results=os_report()
        website_results=website_report()

        print(website_results)

        data = {

            'results':scan_results,
            'os_results':os_results,
            'website_results':website_results,


            'sqliUrl': sqli_URL, 
            'sqliDescription': 'SQL injection is a vulnerability that allows an attacker to alter backend SQL statements by manipulating the user input. An SQL injection occurs when web applications accept user input that is directly placed into a SQL statement and doesn\'t properly filter out dangerous characters.',
            'sqliImpact': 'An attacker may attack /steal your confidential database, which surely will harm the clients.',
            'sqliRecommendation': 'Your script should filter metacharacters and not allow any other query to proceed.',
            'sqliVulnerability': 'SQL Injection',
            'xssUrl': xss_URL,
            'xssDescription': 'Cross-Site Scripting (XSS) attacks are a type of injection, in which malicious scripts are injected into otherwise benign and trusted websites. XSS attacks occur when an attacker uses a web application to send malicious code, generally in the form of a browser side script, to a different end user.',
            'xssImpact': 'Cross-site scripting (XSS) vulnerabilities continue to remain a major threat to web applications as attackers exploiting XSS attacks can gain control of the user’s account and steal personal information such as passwords, bank account numbers, credit card info, personally identifiable information (PII), social security numbers, and more.',
            'xssRecommendation': 'Sanitizing an input field or validating that the data is in the proper form, ensures that only expected content can be submitted by your visitors.',
            'xssVulnerability': 'Cross Site Scripting (XSS)',
            'lfiUrl': lfi_URL,
            'lfiDescription': 'Sanitizing user input, ensure you have a pre-defined list of both expected and acceptable characters.',
            'lfiImpact': 'Gather usernames via/etc/passwd file Harvest useful information from the log files such as /apache/logs/error.log or /apache/logs/access.log Remotely execute commands via combining this vulnerability with some of other attack vectors such as file upload vulnerability or log injection.',
            'lfiRecommendation': 'Ifi possible, do not permit file paths to be appended directly. Make them hard-coded or selectable from a limited hard-coded path list via an index variable 2 :If you definitely need dynamic path concatenation, ensure that you only accept required characters such as a-Z0-9 and do not allow .., /, %00 (null byte) or any other similar unexpected characters.',
            'lfiVulnerability': 'LFI',
            'csrfUrl': csrf_URL,
            'csrfDescription': 'Cross-Site Request Forgery (CSRF) is an attack that forces an end user to execute unwanted actions on a web application in which they’re currently authenticated. An attacker may trick the users of a web application into executing actions of the attacker’s choosing.',
            'csrfImpact': 'A successful CSRF attack can force the user to perform state changing requests like transferring funds, changing their email address, and so forth. If the victim is an administrative account, CSRF can compromise the entire web application.',
            'csrfRecommendation': 'To prevent from csrf attack token(code) should be generated in the backend while filling the form which make sures that token is specific for the authorized users.',
            'csrfVulnerability': 'Cross-Site Request Forgery (CSRF)',
            'directoryUrl': directory_URL,
            'directoryDescription': 'Directory traversal is an attack which allows attackers to access restricted directories and execute commands outside of the web server\'s root directory.',
            'directoryImpact': 'If a web server or web application is vulnerable to directory traversal attack, the attacker can exploit the vulnerability to reach the root directory and access restricted files and directories.',
            'directoryRecommendation': 'To avoid from getting accessed by the attacker. Message will be displayed of access denied with different error.',
            'directoryVulnerability': 'Directory Traversal',
            'urlRedirectionUrl': urlRedirection_URL,
            'urlRedirectionDescription': 'URL Redirection is a vulnerability which allows an attacker to force users of your application to an untrusted external site.The attack is most often performed by delivering a link to the victim, who then clicks the link and is unknowingly redirected to the malicious website.',
            'urlRedirectionImpact': 'URL Redirection attack may assist an attacker to conduct phishing attacks, trojan distribution, spammers.',
            'urlRedirectionRecommendation': 'To minimize the risk of unwanted redirects, avoid user-controllable data in URLs where possible and carefully sanitize it when it must be used.',
            'urlRedirectionVulnerability': 'URL Redirection',
            'iframeUrl': iframe_URL,
            'iframeDescription': 'Clickjacking is an attack that tricks a user into clicking a webpage element which is invisible or disguised as another element. This can cause users to unwittingly download malware, visit malicious web pages, provide credentials or sensitive information, transfer money, or purchase products online.',
            'iframeImpact': 'It is performed by displaying an invisible page or HTML element, inside an iframe, which can be vulnerable for Clickjacking.',
            'iframeRecommendation': 'To avoid from this attack X-Frame-Options response header is passed as part of the HTTP response of a web page, indicating whether or not a browser should be allowed to render a page inside a FRAME or IFRAME tag.',
            'iframeVulnerability': 'Clickjacking',
            'robotsUrl': robots_URL,
            'robotsDescription': 'Robots.txt file tells search engine crawlers that which pages or files the crawler can or can\'t request from your site.',
            'robotsImpact': 'Web developer or web admin thinks that robots.txt is only to tell web crawlers what to look and what to avoid. But they also have to take care that if the attacker accessed the robots.txt file, he can now easily accessed your main page also.',
            'robotsRecommendation': 'Robot.txt is not a vulnerability, but it is to ensure that administrators should review the contents of the robots.txt file to check if the information is consistent with the policies of their organization.',
            'robotsVulnerability': 'Robots.txt',
            'siteMapXmlUrl': siteMapXml_URL,
            'siteMapXmlDescription': 'A sitemap is a file where you provide information about the pages, videos, and other files on your site, and the relationships between them. You can use a sitemap to provide information about specific types of content on your pages, including video and image content.',
            'siteMapXmlImpact': 'Open Policy Crossdomain.xml file allows other SWF files to make HTTP requests to your web server and see its response. For which using an insecure cross-domain policy file could lead to exploit your site to various attacks.',
            'siteMapXmlRecommendation': 'To evaluate which sites will be allowed to make cross-domain calls. Consider network topology and any authentication mechanisms that will be affected by the configuration or implementation of the cross-domain policy.',
            'siteMapXmlVulnerability': 'SiteMap',
            'autoCompleteUrl': autoComplete_URL,
            'autoCompleteDescription': 'Whenever we login/signup with the username and password in any of the form , the browser asks from the user to save it. From this an attacker with local access could obtain the clear text password from the browser cache.',
            'autoCompleteImpact': 'The user entered its data in these fields might be sensitive and the attacker can steal them from the browser cache.',
            'autoCompleteRecommendation': 'To avoid stealing users\' sensitive data, the password autocomplete should be disabled in sensitive applications. To disable autocomplete, use TYPE=password AUTOCOMPLETE=off',
            'autoCompleteVulnerability': 'AutoComplete',
            'httpUrl': http_URL,
            'httpDescription': 'In terms of security, HTTP is completely fine when browsing the web. It only becomes an issue when you\'re entering sensitive data into form fields on a website. If you\'re entering sensitive data into an HTTP web page, that data is transmitted in cleartext and can be read by anyone.',
            'httpImpact': 'It is performed by displaying an invisible page or HTML element, inside an iframe, which can be vulnerable for Clickjacking.',
            'httpRecommendation': 'Depending on the application, an attacker might carry out the following types of attacks. Such as, Cross-site scripting attack, which can lead to session hijacking and and malicious redirect attacks via the location header.',
            'httpVulnerability': 'Http',
        }
        pdf = render_to_pdf('report.html', data)
        return HttpResponse(pdf, content_type='application/pdf')
    
    except Exception as e:
        print(e)
        errorMessage = "Scan Error"
        return render(request,'home.html',{'errorScan':errorMessage})


def home(request):
    if request.method == 'POST':
        form=ScanForm(request.POST)
        if form.is_valid():
            name = form.cleaned_data['projectname']
            url = form.cleaned_data['url']
            description = form.cleaned_data['description']

            scan=form.save()
            check_http = False

            domain_name = urlparse(url).hostname
            ip =socket.gethostbyname(domain_name)
            date=datetime.datetime.now()

            target=TargetDetails(scan=scan,domain_name=domain_name,ip=ip,report_date=date)
            target.save()

            url1 = url
        
    
            if url1 != "":
                if url1[0:5] == 'https':
                    check_http = False
                    new_url=url1[8:]
                    if new_url[0:3] == 'www':
                        new_url1=new_url[4:]
                    else:
                        new_url1=new_url
                elif url1[0:4] == 'http':
                    check_http = True
                    new_url=url1[7:]
                    if new_url[0:3] == 'www':
                        new_url1=new_url[4:]
                    else:
                        new_url1=new_url
                else:
                    new_url=url1
                    if new_url[0:3] == 'www':
                        new_url1=new_url[4:]
                    else:
                        new_url1=new_url
                if check_http == True:
                    url="http://"+new_url1
                else:
                    url="https://"+new_url1
                if '.' in url:
                 Index = url.index('.')
                else:
                    errorMessage = "Url not found!"
                    return render(request,'home.html',{'failUrl':errorMessage})


                session = requests.Session()
                session.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.157 Safari/537.36"

                try:
            # get the HTML content
                    html = session.get(url).content

            # parse HTML using beautiful soup
                    soup = bs(html, "html.parser")
                except:
                    httpUrl = url[5:]
                    httpUrl = "http"+httpUrl
                    url = httpUrl
                    print(url)
 
                    try:
                # get the HTML content
                        html = session.get(url).content

                # parse HTML using beautiful soup
                        soup = bs(html, "html.parser")
                    except:
                        print("Failed to load url")
                        errorMessage = "Url not found!"
                        return render(request,'home.html',{'failUrl':errorMessage})

 # get the anchor files
            anchor_files = []
            img_files = []
            originalLink = url

            for anchor in soup.find_all("a"):
                if anchor.attrs.get("href"):
                # if the tag has the attribute 'href'
                    anchor_url = urljoin(url, anchor.attrs.get("href"))
                #Parsing URL
                    if anchor_url[0:Index] == url[0:Index]:
                        if ".gif" in anchor_url or ".ico" in anchor_url or ".jpg" in anchor_url or ".png" in anchor_url or ".ico" in anchor_url:
                            if anchor_url not in img_files:
                                img_files.append(anchor_url)
                        else:
                            if anchor_url not in anchor_files:
                                anchor_files.append(anchor_url)

            if url not in anchor_files:
                anchor_files.append(url)

            # get the Image files
            # img_files = []

            for img in soup.find_all("img"):
                if img.attrs.get("src"):
                # if the tag has the attribute 'src'
                    img_url = urljoin(url, img.attrs.get("src"))
                #Parsing URL
                # if img_url[0:Index] == url[0:Index]:
                    img_files.append(img_url)

        # get the JavaScript files
            script_files = []

            for script in soup.find_all("script"):
                if script.attrs.get("src"):
                # if the tag has the attribute 'src'
                    script_url = urljoin(url, script.attrs.get("src"))
                #Parsing URL
                    if script_url[0:Index] == url[0:Index]:
                        script_files.append(script_url)
    # get the CSS files
            css_files = []

            for css in soup.find_all("link"):
                if css.attrs.get("href"):
                # if the link tag has the 'href' attribute
                    css_url = urljoin(url, css.attrs.get("href"))
                #Parsing URL
                    if css_url[0:Index] == url[0:Index]:
                        if ".gif" in css_url or ".ico" in css_url or ".jpg" in css_url or ".png" in css_url or ".ico" in css_url:
                            if css_url not in img_files:
                                img_files.append(css_url)
                        else:
                            if css_url not in css_files:
                                css_files.append(css_url)


            print("Total image files in the page:", len(img_files))
            print("Total script files in the page:", len(script_files))
            print("Total CSS files in the page:", len(css_files))
            print("Total Page links in the page:", len(anchor_files))
        
        # Directory Traversal
            slashIndex = 0
            updatedImgLink = []
            if len(img_files) != 0:
                for imgLinks in img_files:
                    arr = list(imgLinks)
                    for x in reversed(range(len(arr))):
                        if arr[x] == '/':
                            slashIndex = x
                            break
                    link = ""
                    for x in range(0,slashIndex):
                        link += arr[x]
                    if link not in updatedImgLink:
                        updatedImgLink.append(link)
                print(updatedImgLink)
        
            global url_links
            def url_links():
                return anchor_files
        
            global url_imgs
            def url_imgs():
                return updatedImgLink

            global originalUrl
            def originalUrl():
                return originalLink


            directoryImg = url_imgs()
            robots_URL = originalUrl()
            siteMapXml_URL = originalUrl()
            http_URL = originalUrl()
        
            sqli_URL = url_links()
            lfi_URL = url_links()
            xss_URL = url_links()
            csrf_URL = url_links()
            urlRedirection_URL = url_links()
            iframe_URL = url_links()
            # email_URL = url_links()
            autoComplete_URL = url_links()    
            sqliResult = []
            lfiResult = []
            xssResult = []
            csrfResult = []
            urlRedirectionResult = []
            iframeResult = []
            # emailResult = []
            autoCompleteResult = []
            directoryResult = []
            robotsResult = ""
            siteMapXmlResult = ""
            httpResult = ""

            csrf_links = []
            urlRedirection_links = []

            print("--------------Directory Links:-------------\n")
            for url in directoryImg:
                directory_error = directoryErrorFunction(url)
                if directory_error != "":
                    directoryResult.append(url)
                    print("Directory: ",directory_error)
                else:
                    print("No direc")
            print("--------------SQLi Links:-------------\n")
            for url in sqli_URL:
                # Object = attackingPhaseClass(url)
                if "=" in url:
                    sqli_error = sqlInjectionErrorFunction(url)
                    if sqli_error != "":
                        sqliResult.append(url)
                        print(sqli_error)
            print("--------------Lfi/Rfi Links:-------------\n")
            for url in lfi_URL:
                if "page=" in url or "load=" in url or "module=" in url:
                    lfi_error = lfiErrorFunction(url)
                    if lfi_error != "":
                        lfiResult.append(url)
                        print(lfi_error)
            print("--------------XSS Links:-------------\n")
            for url in xss_URL:
                if "=" in url:
                    xss_error = xssErrorFunction(url)
                    if xss_error != "":
                        xssResult.append(url)
                        print(xss_error)
            print("--------------ClickJacking Links:-------------\n")
            for url in iframe_URL:
                iframe_error = clickJackingErrorFunction(url)
                if iframe_error != "":
                    iframeResult.append(url)
                    print(iframe_error)
            print("--------------Robots.txt Links:-------------\n")
            robotTxt = robotTxtFunction(robots_URL)
            if robotTxt != "":
                robotsResult = robots_URL
                print(robotTxt)
            print("--------------sitemap.xml Links:-------------\n")
            siteMap = siteMapXmlFunction(siteMapXml_URL)
            if siteMap != "":
                siteMapXmlResult = siteMapXml_URL
                print(siteMap)
            print("--------------CSRF Links:-------------\n")
            for url in csrf_URL:
                if "user=" in url or "password=" in url or "account=" in url or "accountno=" in url or "username=" in url or "pass=" in url:
                    if url not in csrf_links:
                        csrfResult.append(url)
                        print(url)
                    # csrf_links.append(url)
            print("--------------Url Redirection Links:-------------\n")
            for url in urlRedirection_URL:
                if "url=" in url or "targeturl=" in url or "redirect=" in url or "page=" in url:
                    if url not in urlRedirection_links:
                        urlRedirectionResult.append(url)
                        print(url)
            print("--------------AutoComplete Links:-------------\n")
            for url in autoComplete_URL:
                if "contact" in url or "admin" in url or "login" in url or "signup" in url or "account" in url or "register" in url or "signin" in url or "signout" in url:
                    autoComplete = autoCompleteCheckerFunction(url)
                    if autoComplete != "":
                        autoCompleteResult.append(url)
                        print(autoCompleteResult)
            print("--------------Http/https Links:-------------\n")
            if "https" in http_URL:
                httpResult = ""
                print("Secure Trafic")
            else:
                httpResult = "Insecure Traffic"
                print("Insecure Traffic")

            # Global functions for use in report
            global sqliReport
            def sqliReport():
                return sqliResult
            global lfiReport
            def lfiReport():
                return lfiResult
            global xssReport
            def xssReport():
                return xssResult
            global csrfReport
            def csrfReport():
                 return csrfResult
            global directoryReport
            def directoryReport():
                return directoryResult
            global urlRedirectionReport
            def urlRedirectionReport():
                return urlRedirectionResult
            global iframeReport
            def iframeReport():
                return iframeResult
            global robotsReport
            def robotsReport():
                return robotsResult
            global autoCompleteReport
            def autoCompleteReport():
                return autoCompleteResult
            global siteMapXmlReport
            def siteMapXmlReport():
                return siteMapXmlResult
            global httpReport
            def httpReport():
                return httpResult

            scan_results = [
                ('sqli_scan', sqliResult),
                ('lfi_scan', lfiResult),
                ('xss_scan', xssResult),
                ('csrf_scan', csrfResult),
                ('dir_trav_scan', directoryResult),
                ('url_redir_scan', urlRedirectionResult),
                ('iframe_scan', iframeResult),
                ('robots_scan', robotsResult),
                ('sitemap_scan', siteMapXmlResult),
                ('auto_comp_scan', autoCompleteResult),
                ('http_scan', httpResult)
            ]

            for scan_type, scan_result in scan_results:
                if isinstance(scan_result, list):  # Check if the result is a list
                    for result in scan_result:
                        if result:
                            ScanResult.objects.create(target=target, scan_type=scan_type, scan_result=result)
                else:
                    if scan_result:
                        ScanResult.objects.create(target=target, scan_type=scan_type, scan_result=scan_result)  

            target_details=[]

            print(domain_name+" "+ ip)

            results = nmap_scan(domain_name)
            os_results=os_scan(ip)

            website={'project_name':name,'domain_name':domain_name,'ip':ip,'description':description,'Report_Date':date}

            target_details.append(website)
            
            if results:
                service_details_list = []
                for result in results:
                    print(result)
                    service = ServiceDetails(
                        target=target,
                        name=result['name'],
                        port=result['port'],
                        product=result['product'],
                        version=result['version'],
                        script_name=result['script_name'],
                        script_data=result['script_data'],
                    )
                    service_details_list.append(service)
                ServiceDetails.objects.bulk_create(service_details_list)


            if os_results:
                for os_info in os_results:
                    os_information = OSInformation(target=target, os_name=os_info['OSName'], accuracy=os_info['Accuracy'], os_family=os_info['OSFamily'], os_type=os_info['Type'], vendor=os_info['Vendor'])
                    os_information.save()

            global results_report
            def results_report():
                return results

            global os_report
            def os_report():
                return os_results  

            global website_report
            def website_report():
                return target_details

            return render(request,'result.html',{'os_results':os_results,'results':results,'website':website,'sqliResult':sqliResult,'lfiResult':lfiResult,'xssResult':xssResult,'csrfResult':csrfResult,'directoryResult':directoryResult,'urlRedirectionResult':urlRedirectionResult,'iframeResult':iframeResult,'robotsResult':robotsResult,'siteMapXmlResult':siteMapXmlResult,'autoCompleteResult':autoCompleteResult,'httpResult':httpResult})
    else:
        form=ScanForm()
    return render(request, 'home.html',{'form':form})


def result():
    return render(request, 'result.html')