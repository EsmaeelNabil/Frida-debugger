import {useState, useEffect, useCallback} from "react";
import {toaster} from "evergreen-ui";

export const useAppConnection = ({ socket, deviceId, appName }) => {
  const [state, setState] = useState({
    appDetails: null,
    isLoading: true,
    error: null,
  });

  useEffect(() => {
    if (!socket) {
      setState((prev) => ({
        ...prev,
        error: new Error("Socket not initialized"),
      }));
      return;
    }

    const handleAppData = (data) => {
      setState((prev) => ({
        ...prev,
        appDetails: data,
        isLoading: false,
        error: null,
      }));
    };

    const handleError = (error) => {
      setState((prev) => ({
        ...prev,
        error,
        isLoading: false,
      }));
    };

    try {
      socket.emit("GET_APP", { deviceId, appName });
      socket.on("APP", handleAppData);
      socket.on("error", handleError);
    } catch (error) {
      handleError(error);
    }

    return () => {
      socket.off("APP", handleAppData);
      socket.off("error", handleError);
    };
  }, [socket, deviceId, appName]);

  return state;
};

// hooks/useScriptManagement.js
export const useScriptManagement = ({
  socket,
  deviceId,
  appName,
  appDetails,
  initialScript,
}) => {
  const [code, setCode] = useState(initialScript);
  const [error, setError] = useState(null);

  const handleFileChange = useCallback(
    async (files) => {
      if (!files?.[0]) {
        setCode(initialScript);
        return;
      }

      try {
        const content = await files[0].text();
        setCode(content);
      } catch (error) {
        setError(error);
        toaster.danger("Failed to load script file");
      }
    },
    [initialScript],
  );

  const handleScriptAttach = useCallback(() => {
    try {
      socket.emit("ATTACH_TO_APP", { deviceId, appName, script: code });
      toaster.success("Script attached successfully");
    } catch (error) {
      setError(error);
      toaster.danger("Failed to attach script");
    }
  }, [socket, deviceId, appName, code]);

  const handleAppLaunch = useCallback(() => {
    try {
      socket.emit("LAUNCH_APP", {
        deviceId,
        appIdentifier: appDetails?.identifier,
        script: code,
      });
      toaster.success("App launched with script");
    } catch (error) {
      setError(error);
      toaster.danger("Failed to launch app");
    }
  }, [socket, deviceId, appDetails?.identifier, code]);

  const handleScriptUnload = useCallback(() => {
    try {
      socket.emit("UNLOAD_SCRIPTS");
      toaster.success("Scripts unloaded");
    } catch (error) {
      setError(error);
      toaster.danger("Failed to unload scripts");
    }
  }, [socket]);

  return {
    code,
    setCode,
    error,
    handleFileChange,
    handleScriptAttach,
    handleAppLaunch,
    handleScriptUnload,
  };
};

// hooks/useMessageHandler.js
export const useMessageHandler = (maxMessages = 1000) => {
  const [messages, setMessages] = useState([]);

  const addMessage = useCallback(
    (data) => {
      if (data == null) return;

      setMessages((prev) => {
        const messageStr =
          typeof data === "object" ? JSON.stringify(data) : String(data);

        const newMessages = [...prev, messageStr];
        // Keep only the latest messages if we exceed maxMessages
        return newMessages.slice(-maxMessages);
      });
    },
    [maxMessages],
  );

  const clearMessages = useCallback(() => {
    setMessages([]);
  }, []);

  return {
    messages,
    addMessage,
    clearMessages,
  };
};
