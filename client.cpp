#include <iostream>
#include <map>
#include <string>
#include <vector>
#include <tuple>
#include <sstream>
#include <functional>
#include <stdexcept>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

typedef std::function<void(const std::string &, const std::string &)> Command;

#define HOST "34.254.242.81"
#define PORT 8080

class CommandHandler {
public:
	void registerCommand(const std::string& name, Command command, const std::string& method ="", const std::string& path ="") {
		commands[std::make_tuple(name, method, path)] = command;
	}

	void handleCommand(const std::string& name) {
		for (const auto& kv : commands) {
			if (std::get<0>(kv.first) == name) {
				kv.second(std::get<1>(kv.first), std::get<2>(kv.first)); 
				break;
			}
		}
	}

private:
	std::map<std::tuple<std::string, std::string, std::string>, Command> commands;
};

class InputException : public std::runtime_error {
public:
    InputException() : std::runtime_error("Invalid input.") {}
};

template<typename T>
T prompt(const std::string& message) {
    T input;
    std::cout << message;
    std::cin >> input;

    if (std::cin.fail() || std::cin.eof() || std::cin.bad()) {
        std::cin.clear();
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        throw InputException();
    }
    
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    return input;
}

struct HTTPResponse {
	int status_code = 0;
	std::string body;
	std::map<std::string, std::string> headers;
};


class Client {
public:
	Client(const std::string& host, int port) {
		this->host = host;
		this->port = port;
		this->refreshSocket();
	}
	
	~Client() {
		close(this->socket_fd);
	}

	void refreshSocket() {
		this->socket_fd = socket(AF_INET, SOCK_STREAM, 0);
		if (this->socket_fd < 0) {
			throw std::runtime_error("Failed to create socket");
		}

		struct sockaddr_in server_address;
		server_address.sin_family = AF_INET;
		server_address.sin_port = htons(port);

		if (inet_pton(AF_INET, host.c_str(), &server_address.sin_addr) <= 0) {
			throw std::runtime_error("Invalid address");
		}

		if (connect(this->socket_fd, (struct sockaddr*)&server_address, sizeof(server_address)) < 0) {
			throw std::runtime_error("Failed to connect");
		}
	}

	void send(const std::string& message) {
		ssize_t total = 0;
		ssize_t len = message.size();
		ssize_t bytesleft = len;
		ssize_t n;

		// Keep sending the remaining part of the message
		while(total < len) {
			n = write(socket_fd, message.c_str() + total, bytesleft);
			if (n == -1) { break; }
			total += n;
			bytesleft -= n;
		}

		if (total == 0) {
			throw std::runtime_error("Failed to send message");
		}
	}

	HTTPResponse receive() {
		char buffer[4096] = {0};
        HTTPResponse response;
        std::string data;
        bool headers_done = false;

        while (true) {
            ssize_t valread = read(socket_fd, buffer, sizeof(buffer)-1);
            if (valread <= 0) {
                if (valread < 0)
					throw std::runtime_error("Failed to read from socket");
				else
					break; // connection closed
            }

            buffer[valread] = '\0';  // Null-terminate the buffer to make it a valid C-string
            data += buffer;

            // Check if headers have been received completely
            size_t pos = data.find("\r\n\r\n");
            if (pos != std::string::npos && !headers_done) {
                // Split headers and body
                std::string headers_str = data.substr(0, pos);
                data.erase(0, pos + 4); // 4 characters for "\r\n\r\n"

                // Process headers
                std::stringstream ss(headers_str);
                std::string line;
                while (std::getline(ss, line, '\n')) {
                    line.pop_back(); // remove '\r'
                    if (response.status_code == 0) {
                        // Get status code from the status line
                        response.status_code = std::stoi(line.substr(9, 3));
                    } else {
                        size_t colon_pos = line.find(": ");
                        if (colon_pos != std::string::npos) {
                            std::string header_name = line.substr(0, colon_pos);
                            std::string header_value = line.substr(colon_pos + 2);
                            response.headers[header_name] = header_value;
                        }
                    }
                }
                headers_done = true;
				response.body = data;
				data.clear();
            }

            // If headers are done, everything else is body
            if (headers_done) {
                response.body += data;
                data.clear();
            }
        }

        return response;
    }

	std::string getHost() {
		return host + ":" + std::to_string(port);
	}

private:
	std::string host;
	int port;
	int socket_fd;
};

Client APIclient(HOST, PORT);

class HTTPRequest {
public:

	HTTPRequest() {
		this->method = "GET";
		this->path = "/";
		this->body = "";
		registerHeader("Host", APIclient.getHost());
		registerHeader("User-Agent", "RESTinpeace/1.0");
	}


	HTTPRequest(const std::string& method, const std::string& path, const std::string& body) {
		this->method = method;
		this->path = path;
		this->body = body;
		
		size_t pos = path.find("/");
		if (pos == std::string::npos) {
			throw std::runtime_error("Invalid path");
		}
		host = APIclient.getHost(); 
		this->path = path.substr(pos);

		registerHeader("Host", host);
		registerHeader("User-Agent", "RESTinpeace/1.0");
		if (body.size() > 0){
			registerHeader("Content-Type", "application/json");
			registerHeader("Content-Length", std::to_string(body.size() + 2)); // +2 for \r\n
		}
		registerHeader("Connection", "close");

	}

	std::string toString() {
		std::string request = method + " " + path + " HTTP/1.1\r\n";
		for (auto& header : headers) {
			request += header.first + ": " + header.second + "\r\n";
		}
		for (auto& header : optional_headers) {
			request += header.first + ": " + header.second + "\r\n";
		}
		request += "\r\n";
		request += body + "\r\n";
		return request;
	}

	void registerHeader(const std::string& name, const std::string& value) {
		headers.push_back(std::make_pair(name, value));
	};

	void registerOptionalHeader(const std::string& name, const std::string& value) {
		optional_headers.push_back(std::make_pair(name, value));
	};

private:
	std::string method;
	std::string path;
	std::string host;
	std::vector<std::pair<std::string, std::string>> headers;
    std::vector<std::pair<std::string, std::string>> optional_headers;
	std::string body;
};

class Session {
public:

	HTTPResponse sendRequest() {
		if (!token.empty())
			request.registerOptionalHeader("Authorization", "Bearer " + token);

		if (!session_id.empty())
			request.registerOptionalHeader("Cookie", session_id);
		
		APIclient.refreshSocket();
		APIclient.send(request.toString());
		HTTPResponse response = APIclient.receive();
		return response;
	}

	void setToken(const std::string& token) {
		this->token = token;
	}
	void setSessionId(const std::string& session_id) {
		this->session_id = session_id;
	}

	void setRequest(std::string method, std::string route, std::string body) {
		this->request = HTTPRequest(method, route, body);
	}

private:
	std::string session_id;
	std::string token;
	HTTPRequest request;
};

Session session;

void loginCommand(std::string method, std::string path) {
	try {
		std::string username = prompt<std::string>("username= ");
		std::string password = prompt<std::string>("password= ");

		json body = {
			{"username", username},
			{"password", password}
		};

		session.setRequest(method, path, body.dump());
		HTTPResponse resp = session.sendRequest();
		if (resp.status_code == 200) {
			std::cout << "Login successful!" << std::endl;
			std::string session_id = resp.headers["Set-Cookie"];
			session_id = session_id.substr(0, session_id.find(";")); // Remove ; and everything after
			session.setSessionId(session_id);
		} else if (resp.status_code == 400) {
			std::cout << "Login failed! Invalid credentials" << std::endl;
		} else if (resp.status_code == 204) {
			std::cout << "Login failed! User is already logged in" << std::endl;
		}

	} catch (InputException& e) {
		std::cout << e.what() << std::endl;
		return;
	}


}

void accountRegisterCommand(std::string method, std::string path) {
	try {
		std::string username = prompt<std::string>("username= ");
		std::string password = prompt<std::string>("password= ");

		json body = {
			{"username", username},
			{"password", password}
		};

		session.setRequest(method, path, body.dump());
		HTTPResponse resp = session.sendRequest();
		if (resp.status_code == 201) {
			std::cout << "Account created succesfully!" << std::endl;
		} else if(resp.status_code == 400) {
			std::cout << "Account creation failed! Username is already registered!"<< std::endl;
		}

	} catch (InputException& e) {
		std::cout << e.what() << std::endl;
		return;
	}

	
}

void accessCommand(std::string method, std::string path) {
	session.setRequest(method, path, "");
	HTTPResponse resp = session.sendRequest();
	if (resp.status_code == 200) {
		std::cout << "Access granted!" << std::endl;
		json j = json::parse(resp.body);
		std::string token = j["token"];
		session.setToken(token);
	} else if (resp.status_code == 401) {
		std::cout << "Acces denied! You are not logged in!" << std::endl;
	}
}

void getBooksCommand(std::string method, std::string path) {
	session.setRequest(method, path, "");
	HTTPResponse resp = session.sendRequest();

	if (resp.status_code == 200) {
		std::cout << "Books:" << std::endl;
		json j = json::parse(resp.body);
		for (auto& book : j) {
			std::cout << "Id: "<< book["id"] << " " << "Title: "<< book["title"] << std::endl;
		}
	} else if (resp.status_code == 403){
		std::cout << "Acces denied! You don't have access to the library!" << std::endl;
	}
}

void getBookCommand(std::string method, std::string path) {
	try {
		int bookId = prompt<int>("book_id= ");
		path.replace(path.find(":bookId"), 8, std::to_string(bookId));
		session.setRequest(method, path, "");
		HTTPResponse resp = session.sendRequest();

		if (resp.status_code == 200) {
			std::cout << "Book:" << std::endl;
			json j = json::parse(resp.body);
			std::cout <<"Id: " << j["id"] << " " << "Title: " << j["title"] << " " << "Author: " << j["author"] << " " << "Genre: " << j["genre"] << " " << "Page count: " << j["page_count"] << " " << "Publisher: " << j["publisher"] << std::endl;
		} else if (resp.status_code == 404) {
			std::cout << "Book not found!" << std::endl;
		} else if (resp.status_code == 403){
			std::cout << "Acces denied! You don't have access to the library!" << std::endl;
		}
	} catch (InputException& e) {
		std::cout << e.what() << std::endl;
		return;
	}
}

void addBookCommand(std::string method, std::string path) {
	try {
		std::string title = prompt<std::string>("title= ");
		std::string author = prompt<std::string>("author= ");
		std::string genre = prompt<std::string>("genre= ");
		std::string publisher = prompt<std::string>("publisher= ");
		int page_count = prompt<int>("page_count= ");

		json body = {
			{"title", title},
			{"author", author},
			{"genre", genre},
			{"page_count", page_count},
			{"publisher", publisher}

		};

		session.setRequest(method, path, body.dump());
		HTTPResponse resp = session.sendRequest();

		if (resp.status_code == 200) {
			std::cout << "Book added!" << std::endl;
		} else if (resp.status_code == 403) {
			std::cout << "Acces denied! You don't have access to the library!" << std::endl;
		}
	} catch (InputException& e) {
		std::cout << e.what() << std::endl;
		return;
	}
}

void deleteBookCommand(std::string method, std::string path) {
	try {
		int bookId = prompt<int>("book_id= ");
		path.replace(path.find(":bookId"), 8, std::to_string(bookId));
		session.setRequest(method, path, "");
		HTTPResponse resp = session.sendRequest();

		if (resp.status_code == 200) {
			std::cout << "Book deleted!" << std::endl;
		} else if (resp.status_code == 404) {
			std::cout << "Book not found!" << std::endl;
		} else if (resp.status_code == 403) {
			std::cout << "You don't have access to the library!" << std::endl;
		}
	} catch (InputException& e) {
		std::cout << e.what() << std::endl;
		return;
	}
}

void logoutCommand(std::string method, std::string path) {
	session.setRequest(method, path, "");
	HTTPResponse resp = session.sendRequest();
	if (resp.status_code == 200) {
		std::cout << "Logged out!" << std::endl;
		session.setToken("");
		session.setSessionId("");
	} else if (resp.status_code == 400){
		std::cout << "You are not logged in!" << std::endl;
	}
}

void exitCommand(std::string _, std::string __) {
	return;
}

int main() {
	CommandHandler handler;
	
	handler.registerCommand("login", loginCommand, "POST", "/api/v1/tema/auth/login");
	handler.registerCommand("register", accountRegisterCommand, "POST", "/api/v1/tema/auth/register");
	handler.registerCommand("enter_library", accessCommand, "GET", "/api/v1/tema/library/access");
	handler.registerCommand("get_books", getBooksCommand, "GET", "/api/v1/tema/library/books");
	handler.registerCommand("get_book", getBookCommand, "GET", "/api/v1/tema/library/books/:bookId");
	handler.registerCommand("add_book", addBookCommand, "POST", "/api/v1/tema/library/books");
	handler.registerCommand("delete_book", deleteBookCommand, "DELETE", "/api/v1/tema/library/books/:bookId");
	handler.registerCommand("logout", logoutCommand, "GET", "/api/v1/tema/auth/logout");
	handler.registerCommand("exit", exitCommand);


	while (true) {
		std::string command;
		std::cin >> command;
		handler.handleCommand(command);
		if (command == "exit") {
			break;
		}
	}

	return 0;
}
