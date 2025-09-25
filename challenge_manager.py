import requests
import json


def get_challenge(email, challenge):
    """
    Receives information from the challenge URL.
    
    Args:
        email (str): The email parameter for the URL
    
    Returns:
        dict: The response data from the challenge endpoint
    """
    url = f"https://ciberseguridad.diplomatura.unc.edu.ar/cripto/{challenge}/{email}/challenge"
    
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raises an HTTPError for bad responses
        
        # Try to parse as JSON, fallback to text if not JSON
        try:
            data = response.json()
        except json.JSONDecodeError:
            data = {"content": response.text}
            
        return data
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching challenge: {e}")
        return None


def submit_answer(email, answer, challenge):
    """
    Sends a POST request with the answer to the answer endpoint.
    
    Args:
        email (str): The email parameter for the URL
        answer (str): The answer to submit as a decimal number
    
    Returns:
        dict: The response from the server
    """
    url = f"https://ciberseguridad.diplomatura.unc.edu.ar/cripto/{challenge}/{email}/answer"
    
    # Prepare the form data to send
    # Convert answer to integer to ensure it's a proper number
    try:
        number_value = int(answer)
    except ValueError:
        print(f"Error: '{answer}' is not a valid number")
        return None
    
    # Send as form data using files parameter (as shown in the example)
    files = {"number": str(number_value).encode('ascii')}
    
    try:
        response = requests.post(url, files=files)
        response.raise_for_status()
        
        # Print the response
        print(f"Response status: {response.status_code}")
        print(f"Response content: {response.text}")
        
        # Try to parse as JSON, fallback to text if not JSON
        try:
            return response.json()
        except json.JSONDecodeError:
            return {"content": response.text}
            
    except requests.exceptions.RequestException as e:
        print(f"Error submitting answer: {e}")
        return None


# Example usage
if __name__ == "__main__":
    # Example usage
    email = "diegooleiarz@hotmail.com"
    challenge = ""
    
    # Get the challenge
    print("Fetching challenge...")
    challenge_data = get_challenge(email, challenge)
    if challenge_data:
        print("Challenge data:", challenge_data)
    
    # # Submit an answer
    # print("\nSubmitting answer...")
    # answer = ""
    # result = submit_answer(email, answer, challenge)
    # if result:
    #     print("Submission result:", result)
