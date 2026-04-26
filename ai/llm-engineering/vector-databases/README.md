# Vector Databases

A vector database is a specialized type of database designed to store, index, and query high-dimensional vector data efficiently. Unlike traditional databases, which store data in tabular form and are optimized for exact matches, vector databases are built to handle complex data types such as images, text embeddings, and other forms of high-dimensional data through vector embeddings. These vectors are numerical representations of data objects and are used in applications requiring similarity search and pattern recognition.

These are some of the most popular vector databases and related technologies:

1. **[MongoDB Atlas Vector Search](https://www.mongodb.com/products/platform/atlas-vector-search)**
   - This feature of MongoDB Atlas integrates vector search capabilities into the MongoDB database. It allows for efficient similarity searches across high-dimensional data, leveraging MongoDB's existing infrastructure and tools.

2. **[Faiss (Facebook AI Similarity Search)](https://github.com/facebookresearch/faiss/wiki/)**
   - Faiss is an open-source library developed by Facebook AI Research for efficient similarity search and clustering of dense vectors. It is known for its high-speed search performance, scalability, and GPU acceleration capabilities[1][2][6]. However, Faiss is not a full-fledged database but rather a library used to perform vector searches within other systems[2].

3. **[Milvus](https://milvus.io/)**
   - An open-source vector database designed to manage unstructured data efficiently. It supports billion-scale vector data management and provides features like hybrid search for combining sparse and dense vector searches[2].

4. **[Weaviate](https://weaviate.io/)**
   - An open-source vector database that facilitates semantic search and is optimized for distributed systems. It can handle large-scale data and integrates well with machine learning models[3].

5. **[Chroma](https://www.trychroma.com/)**
   - A vector database designed for building LLM applications, offering features like filtering and density estimates. It supports integration with LangChain and LlamaIndex.

## Securing Vector Databases

- [Cisco White Paper: Securing Vector Databases](https://sec.cloudapps.cisco.com/security/center/resources/securing-vector-databases)
- [Milvus Security Best Practices](https://milvus.io/blog/data-security.md)
- [MongoDB Queryable Encryption](https://www.mongodb.com/docs/manual/core/queryable-encryption)
- [MongoDB Client-Side Field Level Encryption](https://www.mongodb.com/docs/manual/core/csfle/)
