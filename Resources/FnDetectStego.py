import os
from PIL import Image
import numpy as np
import matplotlib.pyplot as plt
from scipy import ndimage
from skimage.feature import graycomatrix, graycoprops
from sklearn.cluster import KMeans

#pip install pillow numpy matplotlib scipy scikit-image scikit-learn

def load_image(image_path):
    """
    Load an image from the given path and convert it to grayscale.
    """
    try:
        # Remove any extra quotes from the path
        clean_path = image_path.strip('"')
        
        # Check if the file exists
        if not os.path.exists(clean_path):
            print(f"Error: File not found at {clean_path}")
            return None
        
        img = Image.open(clean_path)
        img_gray = img.convert('L')
        img_array = np.array(img_gray)
        return img_array
    except Exception as e:
        print(f"Error loading image: {str(e)}")
        return None

def statistical_analysis(img_array):
    """
    Perform statistical analysis on the image array.
    """
    mean_value = np.mean(img_array)
    std_dev = np.std(img_array)
    skewness = np.mean(((img_array - mean_value) / std_dev) ** 3)
    kurtosis = np.mean(((img_array - mean_value) / std_dev) ** 4) - 3
    return mean_value, std_dev, skewness, kurtosis

def noise_analysis(img_array):
    """
    Perform noise analysis on the image array.
    """
    noise = img_array - np.mean(img_array)
    noise_std = np.std(noise)
    snr = np.mean(img_array) / noise_std if noise_std != 0 else float('inf')
    return noise_std, snr

def histogram_analysis(img_array):
    """
    Perform histogram analysis on the image array.
    """
    hist, bins = np.histogram(img_array, bins=256, range=(0, 256))
    return hist, bins

def correlation_analysis(img_array):
    """
    Perform correlation analysis on the image array.
    """
    # Calculate correlation between adjacent rows
    corr_rows = np.corrcoef(img_array[:-1], img_array[1:])
    # Calculate correlation between adjacent columns
    corr_cols = np.corrcoef(img_array[:, :-1], img_array[:, 1:])
    return corr_rows[0, 1], corr_cols[0, 1]

def texture_analysis(img_array):
    """
    Perform texture analysis on the image array using GLCM.
    """
    # Ensure the image has integer values
    img_array = img_array.astype(np.uint8)
    
    # Calculate GLCM for different directions
    distances = [1]
    angles = [0, np.pi/4, np.pi/2, 3*np.pi/4]
    glcm = graycomatrix(img_array, distances, angles, levels=256, symmetric=True, normed=True)
    
    # Calculate texture properties
    contrast = graycoprops(glcm, 'contrast').mean()
    dissimilarity = graycoprops(glcm, 'dissimilarity').mean()
    homogeneity = graycoprops(glcm, 'homogeneity').mean()
    energy = graycoprops(glcm, 'energy').mean()
    correlation = graycoprops(glcm, 'correlation').mean()
    
    return contrast, dissimilarity, homogeneity, energy, correlation

def edge_detection(img_array):
    """
    Perform edge detection on the image array using Sobel filters.
    """
    sobel_x = ndimage.sobel(img_array, axis=0)
    sobel_y = ndimage.sobel(img_array, axis=1)
    magnitude = np.sqrt(sobel_x**2 + sobel_y**2)
    return magnitude

def clustering_analysis(img_array, n_clusters=3):
    """
    Perform clustering analysis on the image array using K-means.
    """
    flattened = img_array.reshape(-1, 1)
    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    kmeans.fit(flattened)
    centroids = kmeans.cluster_centers_
    labels = kmeans.labels_.reshape(img_array.shape)
    return labels, centroids

def detect_hidden_data(image_path, technique):
    """
    Detect hidden data in the image using the specified technique.
    """
    img_array = load_image(image_path)
    if img_array is None:
        return None

    result = None
    if technique == 1:
        result = statistical_analysis(img_array)
        print("Statistical Analysis:")
        print(f"Mean: {result[0]:.2f}")
        print(f"Standard Deviation: {result[1]:.2f}")
        print(f"Skewness: {result[2]:.2f}")
        print(f"Kurtosis: {result[3]:.2f}")
    elif technique == 2:
        result = noise_analysis(img_array)
        print("Noise Analysis:")
        print(f"Noise Standard Deviation: {result[0]:.2f}")
        print(f"Signal-to-Noise Ratio: {result[1]:.2f}")
    elif technique == 3:
        result = histogram_analysis(img_array)
        print("Histogram Analysis:")
        plt.figure(figsize=(10, 6))
        plt.bar(result[1][:-1], result[0], width=1)
        plt.xlabel("Pixel Value")
        plt.ylabel("Frequency")
        plt.title("Image Histogram")
        plt.show()
    elif technique == 4:
        result = correlation_analysis(img_array)
        print("Correlation Analysis:")
        print(f"Row correlation: {result[0]:.4f}")
        print(f"Column correlation: {result[1]:.4f}")
    elif technique == 5:
        result = texture_analysis(img_array)
        print("Texture Analysis:")
        print(f"Contrast: {result[0]:.4f}")
        print(f"Dissimilarity: {result[1]:.4f}")
        print(f"Homogeneity: {result[2]:.4f}")
        print(f"Energy: {result[3]:.4f}")
        print(f"Correlation: {result[4]:.4f}")
    elif technique == 6:
        result = edge_detection(img_array)
        print("Edge Detection:")
        plt.figure(figsize=(10, 6))
        plt.imshow(result, cmap='gray')
        plt.title("Edge Detection")
        plt.colorbar()
        plt.show()
    elif technique == 7:
        result = clustering_analysis(img_array)
        print("Clustering Analysis:")
        plt.figure(figsize=(10, 6))
        plt.imshow(result[0], cmap='viridis')
        plt.title("Image Clusters")
        plt.colorbar()
        plt.show()
        print(f"Cluster Centroids: {result[1].flatten()}")
    else:
        print("Invalid technique. Please choose a valid number.")
        return None
    
    return result

# Available analysis techniques
techniques = {
    1: 'Statistical Analysis',
    2: 'Noise Analysis',
    3: 'Histogram Analysis',
    4: 'Correlation Analysis',
    5: 'Texture Analysis',
    6: 'Edge Detection',
    7: 'Clustering Analysis'
}

# Main loop
image_path = None
while True:
    if image_path is None:
        image_path = input("Enter the full path to your image file: ")
        image_path = image_path.strip('"')  # Remove any surrounding quotes
        
        # Validate the image path
        if not os.path.exists(image_path):
            print(f"Error: File not found at {image_path}")
            image_path = None
            continue
    
    print("\nChoose the analysis technique:")
    for key, value in techniques.items():
        print(f"{key}: {value}")
    choice = input("Enter the technique number (or 'q' to quit, 'c' to change image): ")
    
    if choice.lower() == 'q':
        break
    elif choice.lower() == 'c':
        image_path = None
        continue
    
    try:
        technique = int(choice)
        if technique in techniques:
            result = detect_hidden_data(image_path, technique)
            if result is not None:
                print("\nAnalysis completed.")
        else:
            print("Invalid technique. Please choose a valid number.")
    except ValueError:
        print("Invalid input. Please enter a valid number, 'q' to quit, or 'c' to change image.")

print("Thank you for using the image analysis tool!")
