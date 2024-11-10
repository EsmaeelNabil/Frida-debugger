import React from "react";
import { Button, TrashIcon, SearchIcon } from "evergreen-ui";

const MessageList = ({ messages, searchQuery }) => {
  const filteredMessages = searchQuery
    ? messages.filter((msg) =>
        msg.toLowerCase().includes(searchQuery.toLowerCase()),
      )
    : messages;

  return (
    <div className="font-mono text-sm">
      <div className="border rounded-lg bg-gray-50">
        <div className="overflow-auto max-h-[500px]">
          {filteredMessages.map((message, index) => (
            <div
              key={index}
              className="flex hover:bg-gray-100 border-b last:border-b-0"
            >
              <div className="p-2 text-gray-500 bg-gray-100 border-r text-right min-w-[50px]">
                {index + 1}
              </div>
              <div className="p-2 whitespace-pre-wrap break-all flex-1">
                {message}
              </div>
            </div>
          ))}
          {filteredMessages.length === 0 && (
            <div className="p-4 text-center text-gray-500">
              No messages to display
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

const MessageViewer = ({ messages, searchQuery, onSearchChange, onClear }) => {
  return (
    <div className="bg-white rounded-xl shadow-sm">
      <div className="px-6 py-4 border-b border-gray-100">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-medium text-gray-800">Messages</h2>
          <Button
            appearance="minimal"
            intent="danger"
            size="small"
            iconBefore={TrashIcon}
            onClick={onClear}
          >
            Clear Messages
          </Button>
        </div>
      </div>
      <div className="p-6">
        <div className="mb-4">
          <div className="relative">
            <SearchIcon className="absolute left-3 top-2.5 text-gray-400" />
            <input
              type="text"
              placeholder="Search messages..."
              className="w-full pl-10 pr-4 py-2 rounded-lg border border-gray-200 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              onChange={(e) => onSearchChange(e.target.value)}
              value={searchQuery}
            />
            {messages.length > 0 && (
              <span className="absolute right-3 top-2.5 text-sm text-gray-400">
                {messages.length} messages
              </span>
            )}
          </div>
        </div>
        <MessageList messages={messages} searchQuery={searchQuery} />
      </div>
    </div>
  );
};

export default MessageViewer;
