# Lab Guide: Image Recognition with TensorFlow and Keras

## **Objective**

To provide students with hands-on experience in developing, training, and evaluating image recognition models using TensorFlow and Keras.

## **Prerequisites**

1. Basic understanding of Python programming.
2. Familiarity with machine learning concepts.
3. Python and necessary libraries installed: TensorFlow and Keras.

## **Lab Outline**

**Introduction to Image Recognition**:
    - Discussing the basics of image recognition and convolutional neural networks (CNN).
   
**Setting Up the Environment**:
    - Installing TensorFlow and Keras:
    
```bash
    pip install tensorflow keras
```

**Image Data Preprocessing**:

- **Step 1**: Importing Necessary Libraries:
```python
    import tensorflow as tf
    from tensorflow.keras import datasets, layers, models
```

- **Step 2**: Loading and Preprocessing Image Data:
```python
    (train_images, train_labels), (test_images, test_labels) = datasets.cifar10.load_data()
    
    # Normalize pixel values to be between 0 and 1
    train_images, test_images = train_images / 255.0, test_images / 255.0
```

**Building a Convolutional Neural Network (CNN)**:

- **Step 3**: Defining the CNN Architecture:
```python
    model = models.Sequential([
        layers.Conv2D(32, (3, 3), activation='relu', input_shape=(32, 32, 3)),
        layers.MaxPooling2D((2, 2)),
        layers.Conv2D(64, (3, 3), activation='relu'),
        layers.MaxPooling2D((2, 2)),
        layers.Conv2D(64, (3, 3), activation='relu')
    ])
```

- **Step 4**: Adding Dense Layers:
```python
    model.add(layers.Flatten())
    model.add(layers.Dense(64, activation='relu'))
    model.add(layers.Dense(10))
```

**Compiling and Training the Model**:

- **Step 5**: Compiling the Model:
```python
    model.compile(optimizer='adam',
                  loss=tf.keras.losses.SparseCategoricalCrossentropy(from_logits=True),
                  metrics=['accuracy'])
```

- **Step 6**: Training the Model:
```python
    history = model.fit(train_images, train_labels, epochs=10, 
                        validation_data=(test_images, test_labels))
```

**Evaluating the Model**:

- **Step 7**: Evaluating the Model and Visualizing Results:
```python
    test_loss, test_acc = model.evaluate(test_images, test_labels, verbose=2)
    
    import matplotlib.pyplot as plt

    plt.plot(history.history['accuracy'], label='accuracy')
    plt.plot(history.history['val_accuracy'], label = 'val_accuracy')
    plt.xlabel('Epoch')
    plt.ylabel('Accuracy')
    plt.ylim([0.5, 1])
    plt.legend(loc='lower right')
    plt.show()
```

## **Resources**

1. [TensorFlow Documentation](https://www.tensorflow.org/api_docs)
2. [Keras Documentation](https://keras.io/api/)

