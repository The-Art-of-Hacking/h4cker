/*
 
 The simple scanner check class for SHELLING.
 Sends all the payloads one after another, supports DNS (network) and sleep (time) feedback channels. Will also automatically support "file" once it becomes a thing.

*/

package burp;

import java.util.List;
import java.util.ArrayList;
import java.net.URL;
import java.util.logging.Level;
import java.util.logging.Logger;
import uk.co.pentest.SHELLING.IntruderPayloadGenerator;
import uk.co.pentest.SHELLING.ShellingTab;


public class DirectScannerCheck extends ShellingScannerCheck {

        private ShellingTab tab;	
        
        private boolean last400Avoid=false; // whether the last request made was replied with a 400/something along these lines AND the payload contained a white char known to break things HTTP message format when used as literal
        private List<IScanIssue> issues;        
        private IHttpRequestResponse attackReq;                  
        
	public DirectScannerCheck(IBurpExtenderCallbacks cb, ShellingTab tab) 
        {           
            super(cb,tab);
            this.tab = tab;
            checkHttpService = null;
	}
	
	@Override
	public int consolidateDuplicateIssues(IScanIssue existingIssue,IScanIssue newIssue) {
		return -1;
	}	        
        
	@Override
	public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse,IScannerInsertionPoint insertionPoint) 
        {            
                this.issues = null;
                if(tab.shellingPanel.scannerChecks==false) return this.issues; // the switch off (scanner is not enabled, goodbye)
                
                // 
                // We will NO LONGER return scanner issues from this method for DNS and file feedback channels (because they are not direct).
                // doActiveScan() will only return scan issues triggered directly by itself, the current running instance (when using file and time as feedback channels).
                
                // All the DNS interactions (synchronous/asynchronous, does not matter at this point) will be watched by the checkCollabSessions() call (triggered by Scanner/Intruder/Export/exit/schedule?)
                // which will, in turn, will use the addScanIssue() API (with the help of code taken from this useful project https://github.com/PortSwigger/manual-scan-issues).
                
                // Hence, checkCollabInteractions() no longer needs to return issues. We just call it BEFORE starting the actual new scan (this should happen even if the method is again manual, in order not to miss any asynchronously called stuff from previous "auto" calls) + DURING + AFTER.
                this.tab.shellingPanel.checkCollabInteractions(false);
                                
                
        	IRequestInfo reqInfo = helpers.analyzeRequest(baseRequestResponse);
		URL url = reqInfo.getUrl();
                int port = url.getPort();
                String loc="";
                int delaySeconds = this.tab.shellingPanel.getDelay();
                delaySeconds -= 4; // small, SMALL tuning to avoid false negatives (making this thing a bit more sensitive); ping -c25 localhost took only 24 seconds and thus stayed undetected
                // while if this becomes an issue do to slow response times, one can always increase the delay in options if false positives show up
                // this delaySeconds shift (4 secs) should be lower the longer the natural response time is
                // but we are not going too introduce intelligent tuning, are we? maybe manual?
                // 
                // in our case localhost is very fast, usually this will not happen
                
		boolean https=false;
                String host = url.getHost();
                if(url.getProtocol()=="https") https=true;
		String urlStr = url.getProtocol()+"://"+url.getHost()+":"+url.getPort()+url.getPath();
		if(!createCheckHttpService(host,port,https))  
                {
                    callbacks.printError("HTTP connection failed");
                    callbacks.issueAlert("HTTP connection failed");
                    return issues;
                }             
                
                // create new generator object with a dedicated collaborator subdomain (if DNS used as feedback channel)
                generator = new IntruderPayloadGenerator("cmd", tab, "scanner", baseRequestResponse, insertionPoint.getInsertionPointName());  
                // the insertion point should deliver the prefix! to bad intruder can't do this
                
                // save the last generator for the purpose of the asynchronous checkForCollabInteractions() method
                if(this.tab.shellingPanel.feedbackChannel=="DNS")
                {
                    loc = generator.loc; // this might be empty as we MIGHT be using a different feedback channel    
                }   
                
                generator.setBase(baseRequestResponse);
                
                int counter=0; // we need to limit the frequency with which we are calling the collabSessions check, for the purpose of performance and good manners
                while(generator.hasMorePayloads())
                {
                    if(tab.shellingPanel.stopAllRunningScans.isSelected()==true) break; // this should allow us to stop the scan (all of them) by ticking off the box, instantly
                    
                    byte[] payload = generator.getNextPayloadSmart(insertionPoint.getBaseValue().getBytes(),this.last400Avoid);               
                    // domain name is now automatically provided by the getNextPayload function, used by both scanner and intruder in cooperation with our session tracking system
                    if(payload.length==1) 
                    { //payload generation failed, move onto next command
			callbacks.printError("Payload generation failed!");
			callbacks.issueAlert("Payload generation failed!");
                        return this.issues;
                    }
                    
                    
                                        // To avoid Burp's default behaviour with automatic encoding of insertion points in Scanner
                    // we replaced "byte [] req = insertionPoint.buildRequest(payload);"
                    // with new BuildUnencodedRequest(helpers).buildUnencodedRequest(insertionPoint, helpers.stringToBytes(payload))
                    // as adviced by Paj: https://support.portswigger.net/customer/portal/questions/17301079-design-new-extension-problem-with-buildrequest-and-url-encode
                    // with his code snippet: https://gist.github.com/pajswigger/c1fff3ce6e5637126ff92bf57fba54e1
                    
                    byte [] req=null;
                    try {
                        req = new BuildUnencodedRequest(helpers).buildUnencodedRequest(insertionPoint, payload);
                    } catch (Exception ex) {
                        Logger.getLogger(DirectScannerCheck.class.getName()).log(Level.SEVERE, null, ex);
                    }
                    
                    //byte [] req = insertionPoint.buildRequest(payload);
                    //callbacks.printError((new String(req))+"\n\n");
                    
                    // 1. time as feedback channel (detecting a delay in the response)
                    //if(tab.shellingPanel.feedbackChannel=="time")
                    //{
                    
                    long millisBefore = System.currentTimeMillis(); // only used for time
                    
                    attackReq = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(),req); // we perform the attack, because we already know the payload                    
                    byte[] resp = attackReq.getResponse();
                    IResponseInfo responseInfo = helpers.analyzeResponse(resp);
                    
                    if(responseInfo.getStatusCode()==400&&this.tab.shellingPanel.includeLiteralWhites.isSelected()==true&&this.tab.shellingPanel.smart400Avoidance.isSelected()) // baddie avoidance
                    {
                        // search the payload
                        for(int l=0;l<payload.length;l++)
                        { 
                            if(this.tab.shellingPanel.containsBaddies(payload))
                            {
                                this.last400Avoid=true; // it simply means: "literal white chars cause 400 responses from this target in this scan task
                                this.tab.shellingPanel.logOutput("A baddie detected, turning 400 avoidance on (means no more literal white chars in this scan task)!");
                                break;
                            }
                        }
                    }
                    
                    long millisAfter = System.currentTimeMillis(); // only used for time
                    
                    // Default trigger threshold for "time" feedback channel is 25 seconds, so the difference has to be at least 15 seconds provided that it takes approx. 10 to get a normal response
                    // anyway, made this customisable to anyone encountering false positives with this method.
                    long diff = millisAfter-millisBefore;
                    if(this.tab.shellingPanel.feedbackChannel=="time"&&diff>delaySeconds*1000) 
                    {
                            this.issues = new ArrayList<IScanIssue>(1);			
                            BinaryPayloadIssue issue;
                            String details="A potential OS command injection vulnerability was detected using time as the feedback channel.<br><br>";
                            details+="The following payload was supplied to the <b>"+insertionPoint.getInsertionPointName()+"</b> input parameter: <b>"+this.helpers.bytesToString(payload)+"</b><br><br>";
                            details+="The server took <b>"+Long.toString(diff)+"</b> miliseconds to respond.<br><br>";
                            details+="Please be aware that delayed response can happen for multiple reasons, therefore comparing response time with the expected time of additional delay introduced by payloads like <b>sleep 25</b> or <b>ping -n25 localhost</b> is prone to false positives. Investigate this instance manually.<br><br>If you are getting too many false positivies, try to increase the delay in SHELLING -> Global settings or consider using a different feedback channel, e.g. DNS.";
                            issue = new BinaryPayloadIssue(callbacks,attackReq,details,"time");
                            //issue.
                            this.issues.add((IScanIssue) issue);
                            // return upon the first hit - we should make this adjustable in the config as well
                            return this.issues; // we don't worry about interrupting anything, it's just our own direct attack and it was successful, we got what we needed, no need to search for more valid payloads
                    }                    
                    
                    // 2. filesystem as a feedback channel needs to be implemented too
                    // if set, it will do nothing here - which is good, as it is up to the user to inspect the filesystem
                    // so far we are good with "time" and "file"
                    // also, "response" will be handled right here once we start supporting it as a feedback channel
                    
                    // now "DNS"
                    
                    // 3. DNS as the feedback channel
                    // So, the point is we do not want to stop sending payloads only because we encountered some collab interaction
                    // as we might be dealing with a response to one of the previous payloads - which is good as we have to report it
                    // but it does not mean we should stop sending payloads unless we can be sure we are dealing with different sessions (different collabLoc).
                    
                    // the check for collab interactions callback run periodically
                    // we could rely entirely on the additional call of this we perform before exiting this method
                    // but the problem is we might get stuck with long scans with the issue staying unnoticed (which would suck soo badly).
                    if(tab.shellingPanel.feedbackChannel=="DNS")
                    {
                        counter++;
                        if(counter%200==0) // check for feedback every 200 requests
                        {                                           
                           this.tab.shellingPanel.checkCollabInteractions(false); // just call it and let it do its job (we could provide it with an argument (locId) so it filters
                           // them out for us... but again, we want this to he handled separately, so it can ALSO catch Intruder-induced hits as Scanner issues (yup, that's the point of it)                           
                           //if(this.issues!=null&&this.issues.size()>0)
                           //{                                
                           // we don't return here because we might be finding a response from a previous scan
                           // and we don't want it to stop our CURRENT                                 
                           //}
                        }                                                
                    }
                }
                // OK there is no more payloads left in the generator
                // now would be the good time to save the shellings_raw payload set in the collabSession, if we want to track it
                // and do likewise with Intruder and export (if the "auto" mode is on)
                
                // we are just about to return null
                if(tab.shellingPanel.feedbackChannel=="DNS")
                {
                    try 
                    {   
                	Thread.sleep(10); 
                        this.tab.shellingPanel.checkCollabInteractions(true); // one last check after the scan is done (enforce this last one even if the previous one happened earlier than the limit
                    } 
                    catch(Exception e) 
                    {
                           // whateva
                    }
                }
                return null;
        }	        
} // end of the class
