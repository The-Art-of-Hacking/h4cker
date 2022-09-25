/*
	Parent abstract class for Active Scan checks to detect Command Injection with Burp Collaborator. 
        Initializes all base values for ScannerCheck sub classes containing issue request/response highlight indices.
*/

package burp;

import java.util.List;
import uk.co.pentest.SHELLING.IntruderPayloadGenerator;

import uk.co.pentest.SHELLING.ShellingTab;

abstract class ShellingScannerCheck implements IScannerCheck {
	protected IBurpExtenderCallbacks callbacks;
	protected IExtensionHelpers helpers;
	//protected ShellingPayloadGenerator generator;	
        protected IntruderPayloadGenerator generator;
        protected IHttpService checkHttpService;
        protected static int counter=0;
	public ShellingScannerCheck(IBurpExtenderCallbacks cb, ShellingTab tab) {
		callbacks = cb;
		helpers = callbacks.getHelpers();
	}
        protected boolean createCheckHttpService(String host, int port, boolean https) 
        {			
            if((host==null) || ((port<1) || (port>65535))) 
            { 
			return false;
            } 
            else if(host.isEmpty() || ((port<1) || (port>65535))) 
            {
			return false;
            }		
            if(checkHttpService==null) 
            { //HttpService object not yet created, attempt to create			
			checkHttpService = helpers.buildHttpService(host,port,https);
            } 
            else 
            { 
                //HttpService object already created, compare to inputted settings and recreate if different
                String currHost = checkHttpService.getHost();
		int currPort = checkHttpService.getPort();
		String currHttps = checkHttpService.getProtocol();
		if(!(currHost.equals(host) && (currPort==port) && (currHttps.equalsIgnoreCase("http"+(https ? "s" : ""))))) 
			checkHttpService = helpers.buildHttpService(host,port,https);	
            }
            return true;
	}
	@Override 
	public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
		return null;
	}
	
	@Override
	public abstract int consolidateDuplicateIssues(IScanIssue existingIssue,IScanIssue newIssue);
	
	@Override
	public abstract List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,IScannerInsertionPoint insertionPoint);
}
