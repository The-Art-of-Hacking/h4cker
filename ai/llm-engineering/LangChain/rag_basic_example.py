from langchain.document_loaders import WebBaseLoader
from langchain.document_transformers import ChunkTransformer
from langchain.embeddings import OpenAIEmbeddings
from langchain.vectorstores import FAISS
from langchain.retrievers import SemanticRetriever
from langchain.prompts import ChatPromptTemplate
from langchain.chat_models import ChatOpenAI
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough

# Step 1: Load documents
loader = WebBaseLoader("https://example.com")
documents = loader.load()

# Step 2: Transform documents
transformer = ChunkTransformer(chunk_size=512)
transformed_documents = transformer.transform(documents)

# Step 3: Create embeddings
embedding_model = OpenAIEmbeddings()
embeddings = embedding_model.embed(transformed_documents)

# Step 4: Store embeddings in a vector store
vector_store = FAISS.from_embeddings(embeddings)

# Step 5: Create a retriever
retriever = SemanticRetriever(vector_store)

# Step 6: Define the prompt template
template = """Answer the question based only on the following context:
{context}

Question: {question}
"""
prompt = ChatPromptTemplate.from_template(template)

# Step 7: Create the language model
model = ChatOpenAI()

# Step 8: Define the output parser
output_parser = StrOutputParser()

# Step 9: Define the RAG pipeline
pipeline = {
    "context": retriever,
    "question": RunnablePassthrough(),
} | prompt | model | output_parser

# Step 10: Invoke the RAG pipeline with a question
question = "What is the capital of France?"
answer = pipeline.invoke({"question": question})

# Step 11: Print the answer
print(answer)
