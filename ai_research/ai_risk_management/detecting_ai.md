# Detecting AI Usage Within a Company: Strategies and Best Practices

You should always perform a comprehensive inventory of existing AI tools and applications within the company. This involves:

- Engaging with different departments to identify any AI tools in use. Common areas include customer service (chatbots), marketing (predictive analytics), and HR (resume screening).
- Reviewing software licenses and subscriptions for AI-related tools.
- Working with IT to audit systems and networks for AI software and services.

## AI BOMs
I [published an article](https://becomingahacker.org/artificial-intelligence-bill-of-materials-ai-boms-ensuring-ai-transparency-and-traceability-82322643bd2a) that explains AI BOMs in detail. In a nutshell, much like a traditional Bill of Materials in manufacturing that lists out all the parts and components of a product, an AI BOM provides a detailed inventory of all components of an AI system. But, what about Software Bill of Materials (SBOMs)? How are they different from AI BOMs? In the case of SBOMs, they are used to document the components of a software application. However, AI BOMs are used to document the components of an AI system, including the model details, architecture, usage, training data, and more.

## Rules to Detect AI
The following list is pretty limited, but you can get an idea on how you can search in code for AI usage by using these rules:
https://github.com/semgrep/semgrep-rules/tree/develop/ai
