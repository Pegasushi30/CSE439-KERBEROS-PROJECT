import requests
import base64
import rsa

# Load the server's public key
with open("public.pem", "rb") as f:
    PUBLIC_KEY = rsa.PublicKey.load_pkcs1(f.read())

def encrypt_and_send_credentials(username, password, public_key):
    credentials = f"username={username}&password={password}"
    encrypted_credentials = base64.b64encode(rsa.encrypt(credentials.encode(), public_key)).decode()
    return encrypted_credentials

def login(username, password):
    base_url = "http://127.0.0.1:8000"
    token_url = f"{base_url}/authorization-and-tgt-creation"
    
    try:
        encrypted_credentials = encrypt_and_send_credentials(username, password, PUBLIC_KEY)
        form_data = {"username": username, "password": encrypted_credentials}
    except Exception as e:
        print(f"Error: {e}")
        return None

    response = requests.post(token_url, data=form_data)

    if response.status_code == 200:
        access_token = response.json()["access_token"]
        print(f"\nLogin successful and user is authenticated. TGT is granted: {access_token}")
        return access_token
    else:
        print(f"Login failed. Status Code: {response.status_code}")
        print(response.json())
        return None

def is_admin_user(token):
    base_url = "http://127.0.0.1:8000"
    user_url = f"{base_url}/users/me"

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(user_url, headers=headers)

    if response.status_code == 200:
        user_data = response.json()
        is_admin = user_data.get("is_admin", False)
        return is_admin
    else:
        print(f"Failed to get user data. Status Code: {response.status_code}")
        print(response.json())
        return False

def update_server_key(token):
    base_url = "http://127.0.0.1:8000"
    update_server_key_url = f"{base_url}/update-server-key"

    headers = {"Authorization": f"Bearer {token}"}

    # Provide an empty string for new_server_key
    data = {"new_server_key": ""}

    response = requests.post(update_server_key_url, headers=headers, json=data)

    if response.status_code == 200:
        result = response.json()
        print(result)
        return result
    else:
        print(f"Failed to update server key. Status Code: {response.status_code}")
        print(response.json())
        return None

def get_current_user(token):
    base_url = "http://127.0.0.1:8000"
    user_url = f"{base_url}/users/me"

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(user_url, headers=headers)

    if response.status_code == 200:
        current_user = response.json()
        print(f"\nUsername: {current_user['username']}")
        print(f"Full Name: {current_user['full_name']}")
        print(f"Email: {current_user['email']}")
        return current_user
    else:
        print(f"Failed to get current user. Status Code: {response.status_code}")
        print(response.json())
        return None


def encrypt_and_send_new_password(new_client_key, public_key):
    new_password = f"{new_client_key}"
    encrypted_new_password = base64.b64encode(rsa.encrypt(new_password.encode(), public_key)).decode()
    return encrypted_new_password

def update_client_key(token, new_client_key):
    base_url = "http://127.0.0.1:8000"
    update_client_key_url = f"{base_url}/update-client-key"

    headers = {"Authorization": f"Bearer {token}"}
    form_data=encrypt_and_send_new_password(new_client_key, PUBLIC_KEY)
    data = {"new_client_key": form_data}
    response = requests.post(update_client_key_url, headers=headers, json=data)

    if response.status_code == 200:
        result = response.json()
        print(result)
        return result
    else:
        print(f"Failed to update client key. Status Code: {response.status_code}")
        print(response.json())
        return None


def get_current_time(token):
    base_url = "http://127.0.0.1:8000"
    current_time_url = f"{base_url}/current-time"

    headers = {"Authorization": f"Bearer {token}"}
    response = requests.get(current_time_url, headers=headers)

    if response.status_code == 200:
        current_time_utc_plus_3 = response.json()["current_time_utc_plus_3"]
        print(f"\nCurrent Time (UTC+3): {current_time_utc_plus_3}")
        return current_time_utc_plus_3
    else:
        print(f"Failed to get current time. Status Code: {response.status_code}")
        print(response.json())
        return None
    
def validate_tgt(tgt):
    base_url = "http://127.0.0.1:8000"
    validate_tgt_adn_tgs_url = f"{base_url}/tgt-validation-and-tgs"

    headers = {"Authorization": f"Bearer {tgt}"}
    data = {"tgt": tgt}
    response = requests.post(validate_tgt_adn_tgs_url, headers=headers, json=data)

    if response.status_code == 200:
        access_token = response.json()["access_token"]
        print(f"TGT is validated and Ticket is generated. Ticket: {access_token}")
        return access_token
    else:
        print(f"Login failed. Status Code: {response.status_code}")
        print(response.json())
        return None

def logout(token):
    base_url = "http://127.0.0.1:8000"
    logout_url = f"{base_url}/logout"
    headers = {"Authorization": f"Bearer {token}"}
    response = requests.post(logout_url, headers=headers)

    if response.status_code == 200:
        print("\nLogout successful.")
    else:
        print(f"Logout failed. Status Code: {response.status_code}")
        print(response.json())
        return None

def main():
    print("///WELCOME TO CSE 439 PROJECT///")
    username = input("Enter username: ")
    password = input("Enter password: ")

    tgt = login(username, password)
    
    if tgt:
        print("\n*************************************************")
        print("1. Enter TGT for getting a TGS to access services")
        print("2. Logout")
        print("*************************************************\n")
        choice1 = input("Choose service:")

        if choice1 == "1":
            scanf_tgt = input("Enter TGT: ")
            tgs_token = validate_tgt(scanf_tgt)
            is_admin = is_admin_user(tgs_token)
            if tgs_token:
                while True:
                    print("\n*******************************")
                    print("1. Get Current User")
                    print("2. Update Client Key")
                    print("3. Get Current Time")
                    if is_admin:
                        print("4. Generate and Update Server Key (Admin Only)")
                    print("5. Logout")
                    print("*******************************\n")
                    choice = input("Choose service: ")

                    if choice == "1":
                        get_current_user(tgs_token)
                    elif choice == "2":
                        new_client_key = input("\nEnter new client key: ")
                        update_client_key(tgs_token, new_client_key)
                    elif choice == "3":
                        get_current_time(tgs_token)
                    elif choice == "4" and is_admin:
                        update_server_key(tgs_token)
                    elif choice == "5":
                        logout(tgs_token)
                        print("Logging out.")
                        break
                    else:
                        print("Invalid service number. Please try again.")

        elif choice1 == "2":
            logout(tgt)
            print("Logging out.")
        else:
            print("Invalid service number. Please try again.")

if __name__ == "__main__":
    main()
