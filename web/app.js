"use strict";

const API_BASE_URL = (window.ENV?.API_BASE_URL || "").replace(/\/$/, "");

const elements = {
  authSection: document.getElementById("authSection"),
  chatSection: document.getElementById("chatSection"),
  authForm: document.getElementById("authForm"),
  authTitle: document.getElementById("authTitle"),
  username: document.getElementById("username"),
  password: document.getElementById("password"),
  submitButton: document.getElementById("submitButton"),
  toggleAuth: document.getElementById("toggleAuth"),
  authMessage: document.getElementById("authMessage"),
  currentUser: document.getElementById("currentUser"),
  logoutButton: document.getElementById("logoutButton"),
  recipient: document.getElementById("recipient"),
  selectRecipient: document.getElementById("selectRecipient"),
  chatMessage: document.getElementById("chatMessage"),
  conversationTitle: document.getElementById("conversationTitle"),
  messages: document.getElementById("messages"),
  messageForm: document.getElementById("messageForm"),
  messageInput: document.getElementById("messageInput"),
  connectionStatus: document.getElementById("connectionStatus"),
};

let registrationMode = false;
let currentUser = null;
let activeRecipient = null;
let accessToken = null;
let socket = null;

function setMessage(element, message, isError = false) {
  element.textContent = message;
  element.style.color = isError ? "#b91c1c" : "#166534";
}

function setConnectionStatus(connected) {
  elements.connectionStatus.textContent = connected
    ? "Connected"
    : "Disconnected";

  elements.connectionStatus.classList.toggle("online", connected);

  elements.connectionStatus.classList.toggle("offline", !connected);
}

function showLogin() {
  elements.authSection.classList.remove("hidden");
  elements.chatSection.classList.add("hidden");
}

function showChat() {
  elements.authSection.classList.add("hidden");
  elements.chatSection.classList.remove("hidden");

  elements.currentUser.textContent = `Signed in as ${currentUser}`;
}

elements.toggleAuth.addEventListener("click", () => {
  registrationMode = !registrationMode;

  elements.authTitle.textContent = registrationMode
    ? "Create your account"
    : "Welcome back";

  elements.submitButton.textContent = registrationMode ? "Register" : "Sign in";

  elements.toggleAuth.textContent = registrationMode
    ? "Already have an account? Sign in"
    : "Create an account";

  elements.password.autocomplete = registrationMode
    ? "new-password"
    : "current-password";

  setMessage(elements.authMessage, "");
});

elements.authForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const username = elements.username.value.trim();
  const password = elements.password.value;

  if (!API_BASE_URL) {
    setMessage(
      elements.authMessage,
      "Backend URL is not configured yet.",
      true,
    );
    return;
  }

  elements.submitButton.disabled = true;

  try {
    const endpoint = registrationMode ? "/api/register" : "/api/login";

    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username,
        password,
      }),
    });

    const result = await response.json();

    if (!response.ok) {
      throw new Error(result.detail || "Authentication failed.");
    }

    if (registrationMode) {
      setMessage(
        elements.authMessage,
        "Registration successful. You can now sign in.",
      );

      registrationMode = false;
      elements.authTitle.textContent = "Welcome back";
      elements.submitButton.textContent = "Sign in";
      elements.toggleAuth.textContent = "Create an account";
      elements.password.value = "";

      return;
    }

    currentUser = result.username;
    accessToken = result.access_token;

    showChat();

    await connectWebSocket();

    setMessage(elements.chatMessage, "Signed in successfully.");
  } catch (error) {
    setMessage(
      elements.authMessage,
      error.message || "Unable to reach the backend.",
      true,
    );
  } finally {
    elements.submitButton.disabled = false;
  }
});

function connectWebSocket() {
  return new Promise((resolve, reject) => {
    if (!API_BASE_URL || !accessToken) {
      reject(new Error("Backend configuration is missing."));
      return;
    }

    const backend = new URL(API_BASE_URL);

    const protocol = backend.protocol === "https:" ? "wss:" : "ws:";

    const wsURL = new URL("/ws", `${protocol}//${backend.host}`);

    wsURL.searchParams.set("token", accessToken);

    socket = new WebSocket(wsURL);

    const timeout = setTimeout(() => {
      socket.close();
      reject(new Error("WebSocket connection timed out."));
    }, 10000);

    socket.addEventListener(
      "open",
      () => {
        clearTimeout(timeout);
        setConnectionStatus(true);
        resolve();
      },
      { once: true },
    );

    socket.addEventListener("message", (event) => {
      handleIncomingMessage(event.data);
    });

    socket.addEventListener("close", () => {
      setConnectionStatus(false);
    });

    socket.addEventListener(
      "error",
      () => {
        clearTimeout(timeout);
        setConnectionStatus(false);
        reject(new Error("Unable to connect to the chat server."));
      },
      { once: true },
    );
  });
}

function handleIncomingMessage(rawData) {
  let data;

  try {
    data = JSON.parse(rawData);
  } catch {
    setMessage(
      elements.chatMessage,
      "Received an invalid server response.",
      true,
    );
    return;
  }

  if (data.type === "error") {
    setMessage(
      elements.chatMessage,
      data.message || "Message operation failed.",
      true,
    );
    return;
  }

  /*
   * Messages must be decrypted and authenticated by a
   * verified client-side cryptographic implementation
   * before their plaintext is displayed.
   *
   * Do not display arbitrary server-provided ciphertext
   * as if it were decrypted text.
   */
  if (data.type === "encrypted_message") {
    setMessage(
      elements.chatMessage,
      "Encrypted message received. Decryption integration is pending.",
    );
  }
}

elements.selectRecipient.addEventListener("click", () => {
  const recipient = elements.recipient.value.trim();

  if (!recipient) {
    setMessage(elements.chatMessage, "Enter a recipient username.", true);
    return;
  }

  if (recipient === currentUser) {
    setMessage(
      elements.chatMessage,
      "You cannot start a conversation with yourself.",
      true,
    );
    return;
  }

  activeRecipient = recipient;

  elements.conversationTitle.textContent = `Conversation with ${recipient}`;

  elements.messages.replaceChildren();

  const emptyState = document.createElement("p");
  emptyState.className = "empty-state";
  emptyState.textContent =
    "Conversation selected. Messaging will be enabled after cryptographic integration.";

  elements.messages.appendChild(emptyState);
});

elements.messageForm.addEventListener("submit", (event) => {
  event.preventDefault();

  if (!socket || socket.readyState !== WebSocket.OPEN) {
    setMessage(elements.chatMessage, "The chat server is not connected.", true);
    return;
  }

  if (!activeRecipient) {
    setMessage(elements.chatMessage, "Select a recipient first.", true);
    return;
  }

  setMessage(
    elements.chatMessage,
    "Sending is disabled until end-to-end encryption is integrated and verified.",
    true,
  );
});

elements.logoutButton.addEventListener("click", () => {
  if (socket) {
    socket.close();
  }

  socket = null;
  accessToken = null;
  currentUser = null;
  activeRecipient = null;

  elements.authForm.reset();
  elements.messageForm.reset();
  elements.messages.replaceChildren();

  setConnectionStatus(false);
  showLogin();

  setMessage(elements.authMessage, "You have signed out.");
});

showLogin();
setConnectionStatus(false);
