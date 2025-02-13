import requests
import json
from typing import Dict, Any,Optional
from groq import Groq
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()


def get_food_image(recipe_name: str) -> Optional[str]:
    try:
        # Pexels API key - you should move this to .env file
        pexels_key = "WS8xdvuEbxfOTkXvAPga9NCqylZvlcRuXohZHfRzRazRMiypmZxsW89N"  # Get one from: https://www.pexels.com/api/
        
        headers = {
            "Authorization": pexels_key
        }
        
        # Make search more specific for food
        search_query = f"{recipe_name} food dish recipe"
        url = "https://api.pexels.com/v1/search"
        
        params = {
            "query": search_query,
            "per_page": 1,
            "orientation": "landscape",
            "size": "large"
        }

        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        
        data = response.json()
        
        if data.get("photos"):
            # Return the large size image URL
            return data["photos"][0]["src"]["large"]
        
        return None

    except Exception as e:
        print(f"Error fetching image: {str(e)}")
        return None
    
def generate_recipe(prompt: str) -> Dict[str, Any]:
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
    - preparation_time: string time in minutes with unit
    - photo_url: a placeholder URL for a food photo
    
    Ensure the response is properly formatted JSON."""

    try:
        # Make the API call using Groq's chat completion
        chat_completion = client.chat.completions.create(
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Generate a detailed recipe for: {prompt}"}
            ],
            model="mixtral-8x7b-32768",
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
            
        # Remove escaped underscores
        json_str = json_str.replace("\\_", "_")
        
        # Parse the cleaned JSON
        recipe_data = json.loads(json_str.strip())
        
        # Try to get a real food image
        image_url = get_food_image(recipe_data["recipe_name"])
        if image_url:
            recipe_data["photo_url"] = image_url
        return recipe_data

    except json.JSONDecodeError as je:
        print(f"JSON parsing error: {str(je)}")
        print(f"Raw response: {response_content}")
        return None
    except Exception as e:
        print(f"Error generating recipe: {str(e)}")
        return None
    
if __name__ == '__main__':
    # Example usage
    test_prompts = [
        "vegetarian lasagna"
    ]
    
    for prompt in test_prompts:
        print(f"\nGenerating recipe for: {prompt}")
        recipe = generate_recipe(prompt)
        if recipe:
            print(json.dumps(recipe, indent=2))
        else:
            print("Failed to generate recipe")