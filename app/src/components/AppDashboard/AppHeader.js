import React from "react";
import IconBuffer from "../IconBuffer";

const AppHeader = ({ appName, appIcon }) => {
  return (
    <div className="bg-white border-b">
      <div className="max-w-6xl mx-auto px-4 py-4">
        <div className="flex items-center space-x-4">
          <div className="w-10 h-10">
            {appIcon && <IconBuffer icon={appIcon} />}
          </div>
          <div>
            <h1 className="text-xl font-semibold text-gray-800">{appName}</h1>
            <p className="text-sm text-gray-500">App Dashboard</p>
          </div>
        </div>
      </div>
    </div>
  );
};

export default AppHeader;
