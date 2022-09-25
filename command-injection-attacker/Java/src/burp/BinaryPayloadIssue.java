

package burp;


public class BinaryPayloadIssue extends ShellingScannerIssue {
	private String issueDetail;
	
	private static final String DETAIL_TEMPLATE = "The target seems vulnerable to OS Command Injection.<br>";
	private static int counter=0;
	public BinaryPayloadIssue(IBurpExtenderCallbacks cb,IHttpRequestResponse exploitRR, String details, String feedbackMethod) {                                          
		super(cb,exploitRR,details,feedbackMethod);
		issueDetail = DETAIL_TEMPLATE;
	}
        public void appendIssueDetail(String text)
        {
                this.issueDetail = this.issueDetail+text;
        }        
	@Override
	public String getIssueDetail() {
		return issueDetail;
	}
}

