
package burp;

import java.net.URL;


abstract public class ShellingScannerIssue implements IScanIssue {
	//IScanIssue fields
	private IHttpRequestResponse[] httpMessages;
	private IHttpService httpService;
	private String remediationBackground;
	private URL url;
        private String confidence="Certain";        
	private String feedbackMethod;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	
	private String ISSUE_BACKGROUND = "Someone is having a good day.<br>";
	private String REM_BACKGROUND = "It's time to play.<br>";
        //private static int counter=0;
	
	ShellingScannerIssue(IBurpExtenderCallbacks cb,IHttpRequestResponse exploitRR, String details, String feedbackMethod) {
		callbacks = cb;                               
		helpers = callbacks.getHelpers();
		url = helpers.analyzeRequest(exploitRR).getUrl();
		httpService = exploitRR.getHttpService();	
		httpMessages = new IHttpRequestResponse[] {exploitRR};                
                this.feedbackMethod=feedbackMethod;
                //counter++;
                //this.feedbackChannel="(SHELLING - "+feedbackMethod+" - "+Integer.toString(this.counter)+")";
                if(feedbackMethod=="time")
                {
                    this.confidence="Tentative"; // let's be honest with our users
                }                
                ISSUE_BACKGROUND = ISSUE_BACKGROUND + details; // let's see if this will fool the 'duplicate-detection' algorithm or whatever has been making our "details" global up until now                
                //REM_BACKGROUND = "";
	}
	
	//IScanIssue methods
	@Override
	public String getConfidence() {
		return this.confidence;
	}
	
	@Override
	public IHttpRequestResponse[] getHttpMessages() {
		return httpMessages;
	}
	
	@Override
	public IHttpService getHttpService() {
		return httpService;
	}
	
	@Override
	public String getIssueBackground() {
		return ISSUE_BACKGROUND;
	}
	
	@Override
	public abstract String getIssueDetail();
	
	@Override
	public String getIssueName() {
		return "Command Injection (SHELLING-"+this.feedbackMethod+")";
	}
	
	@Override
	public int getIssueType() {
		return 0;
	}
	
	@Override
	public String getRemediationBackground() {
		return REM_BACKGROUND;
	}
	
	@Override
	public String getRemediationDetail() {
		return null;
	}	
	@Override
	public String getSeverity() {
		return "High";
	}
	
	@Override
	public URL getUrl() {
		return url;
	}
}
