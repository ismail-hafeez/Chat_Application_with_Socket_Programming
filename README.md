# Advanced Chat Application with Socket Programming

This assignment involves developing an advanced chat application using socket programming in C/C++ . The system will support multiple clients communicating via TCP (reliable) and UDP (fast) protocols. Unlike a basic chat system, this version includes enhanced features such as:
- User authentication (username + simple password)
- Private messaging (/msg command)
- File sharing (/file command)
- User status updates (online, away, busy)
- Message history (/history command)
- Notifications for joins/leaves

The focus remains on socket programming , multi -client handling , and protocol differences (TCP vs. UDP).

## Objectives
- Support multiple concurrent users
- Implement both TCP and UDP for different tasks
- Allow private messaging and file transfers
- Maintain a message history (last 100 messages)
- Log user connections/disconnections with timestamps
- Handle user status updates (online/away/busy)
- Include a command -based interface (/help, /exit, etc.)
