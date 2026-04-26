# AI Ethics and Privacy Resources


### Databases for Human Activity Recognition:

1. **[MobiAct](https://github.com/MatheLi/Fall_Detection_App_AI/blob/master/posts/The_dataset.md)**  
   A dataset optimized for detecting activities such as falls, walking, and jogging. It is primarily used in creating apps that use smartphone sensors to detect falls, particularly in elderly individuals.

2. **[NHANES Dataset](http://www.sal.disco.unimib.it/technologies/unimib-shar/)**  
   Although not exclusively designed for HAR, the NHANES dataset is a rich source of health and nutritional data, which could potentially be utilized to garner insights into human activities and health conditions.

3. **[UniMiB SHAR](https://wwwn.cdc.gov/nchs/nhanes/)**  
   This repository houses data concerning human activities collected from smartphone accelerometer sensors. It serves as a valuable resource for developing machine learning models capable of recognizing various activities.

4. **[UCI Human Activity Recognition Using Smartphones Dataset](https://archive.ics.uci.edu/dataset/240/human+activity+recognition+using+smartphones)**  
   This dataset comprises data from smartphone accelerometers and gyroscopes, capturing activities such as walking, sitting, and standing performed by 30 subjects. It is a popular choice for HAR research projects.

5. **[ISDM (Wireless Sensor Data Mining)](https://github.com/topics/wireless-sensor-data-mining)**  
   Although not a database per se, this GitHub topic connects you to various resources and datasets pertaining to wireless sensor data mining, an essential aspect in HAR research.

6. **[HHAR (Heterogeneity Human Activity Recognition)](https://github.com/Limmen/Distributed_ML)**  
   HHAR stands out with its data collected from a range of devices, portraying various human activities. It is particularly beneficial for constructing models adaptable to different data sources.

7. **[PAMAP2 Physical Activity Monitoring](https://archive.ics.uci.edu/dataset/231/pamap2+physical+activity+monitoring)**  
   Featuring data from wearable sensors monitoring individuals performing diverse physical activities, PAMAP2 is a vital tool for developing predictive HAR models.

8. **[Daphnet Freezing of Gait](https://archive.ics.uci.edu/dataset/245/daphnet+freezing+of+gait)**  
   Focused on Parkinson's patients' gait freezing, this dataset, comprising data from wearable sensors, plays a crucial role in HAR healthcare applications.

9. **[Actitracker](https://github.com/gomahajan/har-actitracker)**  
   Developed to recognize various physical activities through smartphone sensors, Actitracker houses data on activities such as walking and jogging.

10. **[Daily and Sports Activities](https://archive.ics.uci.edu/dataset/256/daily+and+sports+activities)**  
    This dataset contains data on a range of daily and sports activities recorded through wearable sensors, making it a rich resource for HAR research, especially in distinguishing between different physical activities.

11. **[Smartphone Dataset for Human Activity Recognition (HAR) in Ambient Assisted Living (AAL)](https://archive.ics.uci.edu/dataset/364/smartphone+dataset+for+human+activity+recognition+har+in+ambient+assisted+living+aal)**  
    This dataset focuses on aiding the elderly or disabled, using smartphone sensors to identify their activities, hence fostering safer and more comfortable living environments.

12. **[Opportunity Activity Recognition](https://archive.ics.uci.edu/dataset/226/opportunity+activity+recognition)**  
    This dataset is notable for its emphasis on context recognition, using sensor data from various sources to identify complex activities and gestures, thereby advancing research in ambient intelligence.

13. **[CASAS](https://casas.wsu.edu/datasets/)**  
    CASAS, a collection of datasets centered on smart home environments, facilitates the creation of algorithms capable of recognizing home-based activities through sensor data.

14. **[MSR Daily Activity 3D](https://wangjiangb.github.io/my_data.html)**  
    This dataset distinguishes itself with its inclusion of depth maps alongside skeletal data for activity recognition, aiding in the development of models capable of identifying activities from 3D data.

15. **[REALDISP Activity Recognition Dataset](https://mldta.com/dataset/realdisp-activity-recognition-dataset/)**  
    REALDISP incorporates data on various activities captured through wearable sensors, with a focus on realistic data disposition, which is vital for creating robust HAR models.

### Tools & Methods for Data Collection, Cleaning, and Analysis:

- **Data Collection**:
  - APIs and SDKs
  - Wireless transmission

### Data Cleaning:

3. **Pandas**:
   - **Example**: Cleaning a dataset with missing values using Pandas before training a machine learning model.
   - **Relevant Link**: [Pandas Documentation](https://pandas.pydata.org/pandas-docs/stable/index.html)
   - **Usage in HAR and AI**: Pandas can be used to structure and clean sensor data, making it suitable for training AI models capable of recognizing complex patterns in human activity data.

4. **Sci-kit learn**:
   - **Example**: Using Sci-kit learn for feature selection and removing irrelevant features from a dataset.
   - **Relevant Link**: [Sci-kit learn Documentation](https://scikit-learn.org/stable/)
   - **Usage in HAR and AI**: Sci-kit learn offers various tools for data preprocessing, which is a vital step in preparing data for AI algorithms, enhancing the performance of the models in HAR applications.

### Data Analysis:

5. **TensorFlow**:
   - **Example**: Developing a deep learning model using TensorFlow to classify different activities based on sensor data.
   - **Relevant Link**: [TensorFlow Documentation](https://www.tensorflow.org/learn)
   - **Usage in HAR and AI**: TensorFlow provides a comprehensive platform for developing and training AI models capable of analyzing and recognizing patterns in human activity data.

6. **Keras**:
   - **Example**: Using Keras to create a convolutional neural network (CNN) for image recognition, an essential task in AI.
   - **Relevant Link**: [Keras Documentation](https://keras.io/getting_started/intro_to_keras_for_engineers/)
   - **Usage in HAR and AI**: Keras simplifies the process of building and optimizing neural networks, a crucial component in AI, to analyze human activity data more effectively and make predictions.

### Visualization and Further Analysis:

7. **Matplotlib**:
   - **Example**: Using Matplotlib to visualize the distribution of different activities within a dataset.
   - **Relevant Link**: [Matplotlib Documentation](https://matplotlib.org/stable/contents.html)
   - **Usage in HAR and AI**: Visualization of data is essential in AI to understand underlying patterns and trends in data, aiding in the better development and tuning of models for HAR.

8. **Seaborn**:
   - **Example**: Creating a heatmap using Seaborn to visualize the correlation between different features in a dataset.
   - **Relevant Link**: [Seaborn Documentation](https://seaborn.pydata.org/)
   - **Usage in HAR and AI**: Seaborn can enhance data visualization in AI, assisting in identifying relationships and patterns in data which can influence the development and performance of HAR models.

