# Post-engagement Cleanup

By following these best practices, you ensure that the system is returned to its original state as closely as possible, minimizing any risks or disruptions to the client.

### 1. Documentation

- **List of Changes**: Maintain a detailed log of all the changes you've made during the test, such as uploaded files, created accounts, or modified configurations. 
- **Cleanup Checklist**: Develop a checklist based on the list of changes to ensure nothing is missed during cleanup.

### 2. Data Removal

- **Uploaded Files**: Delete any payloads, backdoors, or files that were uploaded during the test.
- **Test Data**: Remove any data that was created during the test, like dummy users or database entries.

### 3. Account De-provisioning

- **User Accounts**: Disable or remove any user accounts that were created.
- **API Tokens**: Revoke any API keys or tokens that were generated.

### 4. Configuration Reversion

- **System Changes**: Revert any system or network changes made during the test, such as firewall rules, routing changes, or altered services.
- **Code Changes**: If any temporary code changes were made, ensure they are reverted to their original state.

### 5. Log Review

- **Logs**: Review logs to ensure all actions taken during the test are removed or annotated, so they are not mistaken for malicious activities later on.
- **Incident Systems**: Ensure that any alerts or incidents generated during the test are closed or annotated in the Incident Management System.

### 6. Notification

- **Stakeholder Notification**: Notify all relevant stakeholders that the cleanup process has been completed and that the system is back to its original state.
- **Time Synchronization**: Confirm that the time and date of completion align with what was agreed upon in the initial scope.

### 7. Validation

- **System Checks**: Conduct a final round of checks to ensure all systems are functioning as expected.
- **Security Checks**: Run a quick vulnerability scan or checklist to ensure that the cleanup process didn't introduce new vulnerabilities.

### 8. Final Report Update

- **Cleanup Documentation**: Update the final report to include a section detailing the cleanup actions taken.
- **Client Sign-off**: Obtain client acknowledgment that the cleanup has been completed to their satisfaction.

### 9. Lessons Learned

- **Review**: Conduct a lessons-learned meeting with your team to discuss what went well and what could be improved in the cleanup process for future engagements.

### 10. Legal and Ethical Responsibilities

- **Data Handling**: Ensure that all sensitive data obtained during testing is securely deleted.
- **Compliance**: Ensure that all actions are in line with legal requirements and ethical guidelines.

