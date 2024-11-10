import React from "react";
import {
  FilePicker,
  Button,
  EditIcon,
  CleanIcon,
  RedoIcon,
  TrashIcon,
} from "evergreen-ui";

const ScriptManagement = ({
  onFileChange,
  onOpenEditor,
  onAttach,
  onLaunch,
  onUnload,
  isAttachDisabled,
}) => {
  return (
    <div className="bg-white rounded-xl shadow-sm mb-6">
      <div className="px-6 py-4 border-b border-gray-100">
        <h2 className="text-lg font-medium text-gray-800">Script Management</h2>
      </div>
      <div className="p-6">
        <div className="flex items-center gap-4 mb-6">
          <div className="flex-grow">
            <FilePicker
              className="w-full"
              accept=".js"
              onChange={onFileChange}
              placeholder="Select a JavaScript file..."
            />
          </div>
          <Button
            appearance="primary"
            intent="success"
            iconBefore={EditIcon}
            onClick={onOpenEditor}
            className="whitespace-nowrap"
          >
            Open Editor
          </Button>
        </div>

        <div className="flex flex-wrap gap-3">
          <Button
            appearance="default"
            intent="none"
            iconBefore={CleanIcon}
            onClick={onAttach}
            disabled={isAttachDisabled}
            className="hover:bg-gray-100"
          >
            Attach Script
          </Button>
          <Button
            appearance="default"
            intent="success"
            iconBefore={RedoIcon}
            onClick={onLaunch}
            className="hover:bg-green-50"
          >
            Launch App
          </Button>
          <Button
            appearance="default"
            intent="danger"
            iconBefore={TrashIcon}
            onClick={onUnload}
            className="hover:bg-red-50"
          >
            Unload Scripts
          </Button>
        </div>
      </div>
    </div>
  );
};

export default ScriptManagement;
