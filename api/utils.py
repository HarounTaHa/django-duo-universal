from rest_framework.response import Response


def standardized_response(status_bool, message, data=None, status_code=200):
    """
    Create a standardized response format for all API endpoints

    Args:
        status_bool (bool): True for success, False for error
        message (str): Message to be displayed to the user
        data (dict, optional): Data to be returned. Defaults to {}.
        status_code (int, optional): HTTP status code. Defaults to 200.

    Returns:
        Response: Django REST Framework Response with standardized format
    """
    if data is None:
        data = {}

    response_data = {
        "status": status_bool,
        "message": message,
        "data": data
    }

    return Response(response_data, status=status_code)  # Step 10: Sample .env file and setup commands
