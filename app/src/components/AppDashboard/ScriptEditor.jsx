import React from "react";
import { Dialog } from "evergreen-ui";
import Editor from "react-simple-code-editor";
import { highlight, languages } from "prismjs/components/prism-core";
import "prismjs/components/prism-clike";
import "prismjs/components/prism-javascript";
import "prismjs/themes/prism.css";

const ScriptEditor = ({ isShown, onClose, code, onCodeChange }) => {
  return (
    <Dialog
      isShown={isShown}
      title="Script Editor"
      onCloseComplete={onClose}
      width="80%"
      hasFooter={true}
      confirmLabel="Save Changes"
      intent="success"
      onConfirm={onClose}
    >
      <div className="border rounded-lg overflow-hidden bg-white">
        <div className="bg-gray-100 px-4 py-2 border-b flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <div className="w-3 h-3 rounded-full bg-red-400" />
            <div className="w-3 h-3 rounded-full bg-yellow-400" />
            <div className="w-3 h-3 rounded-full bg-green-400" />
          </div>
          <div className="text-xs text-gray-500">script.js</div>
        </div>
        <Editor
          value={code}
          onValueChange={onCodeChange}
          highlight={(code) => highlight(code, languages.js)}
          padding={16}
          style={{
            fontFamily: '"Fira Code", "Fira Mono", monospace',
            fontSize: 14,
            minHeight: "400px",
            backgroundColor: "#ffffff",
          }}
          className="border-0 focus:outline-none"
        />
      </div>
    </Dialog>
  );
};

export default ScriptEditor;
