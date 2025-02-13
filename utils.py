import requests
import json
from typing import Dict, Any
from groq import Groq
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

def generate_recipe(prompt: str) -> Dict[str, Any]:
    """
    Generate a recipe using the Groq API based on a prompt.
    Returns a structured recipe dictionary.
    """
    # Initialize Groq client with API key from environment variable
    client = Groq(
        api_key=os.getenv('GROQ_API_KEY', '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')
    )

    system_prompt = """You are a professional chef. Generate a recipe in valid JSON format.
    The recipe must include:
    - recipe_name: string
    - category_name: one of [Italian, French, Asian, American, Mexican, Mediterranean]
    - recipe_intro: brief introduction
    - ingredients: list of ingredients with measurements
    - description: step by step instructions
    - preparation_time: time in minutes (number)
    - photo_url: a placeholder URL for a food photo
    
    Ensure the response is properly formatted JSON."""

    try:
        # Make the API call using Groq's chat completion
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Generate a detailed recipe for: {prompt}"}
            ],
            model="mixtral-8x7b-32768",  # Using Mixtral model for better performance
            temperature=0.7,
            max_tokens=2048,
            top_p=0.9
        )
        
        # Get the response content
        response_content = chat_completion.choices[0].message.content
        
        # Clean and parse the JSON response
        # Remove any potential markdown formatting
        json_str = response_content.strip()
        if json_str.startswith("```json"):
            json_str = json_str[7:-3]  # Remove ```json and ``` markers
        
        # Parse the cleaned JSON
        recipe_data = json.loads(json_str.strip())
        return recipe_data

    except json.JSONDecodeError as je:
        print(f"JSON parsing error: {str(je)}")
        print(f"Raw response: {response_content}")
        return None
    except Exception as e:
        print(f"Error generating recipe: {str(e)}")
        return None
