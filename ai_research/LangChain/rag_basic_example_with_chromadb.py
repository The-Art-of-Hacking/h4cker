from langchain.document_loaders import TextLoader
from langchain.text_splitter import CharacterTextSplitter
from langchain.embeddings import SentenceTransformerEmbeddings
from langchain.vectorstores import Chroma
from langchain.retrievers import SemanticRetriever
from langchain.prompts import ChatPromptTemplate
from langchain.chat_models import ChatOpenAI
from langchain.schema.output_parser import StrOutputParser
from langchain.schema.runnable import RunnablePassthrough

# Step 1: Load the document and split it into chunks
loader = TextLoader("path/to/document.txt")
documents = loader.load()

text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
chunks = text_splitter.split_documents(documents)

# Step 2: Create embeddings
embedding_model = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")
embeddings = embedding_model.embed(chunks)

# Step 3: Store embeddings in ChromaDB
db = Chroma.from_embeddings(embeddings)

# Step 4: Create a retriever
retriever = SemanticRetriever(db)

# Step 5: Define the prompt template
template = """Answer the question based only on the following context:
{context}

Question: {question}
"""
prompt = ChatPromptTemplate.from_template(template)

# Step 6: Create the language model
model = ChatOpenAI()

# Step 7: Define the output parser
output_parser = StrOutputParser()

# Step 8: Define the RAG pipeline
pipeline = {
    "context": retriever,
    "question": RunnablePassthrough(),
} | prompt | model | output_parser

# Step 9: Invoke the RAG pipeline with a question
question = "What is the main theme of the document?"
answer = pipeline.invoke({"question": question})

# Step 10: Print the answer
print(answer)
