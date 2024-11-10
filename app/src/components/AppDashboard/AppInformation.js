import React, { useState } from "react";
import { ChevronDownIcon, ChevronRightIcon } from "evergreen-ui";

const AppInformation = ({ appDetails, appName }) => {
  const [isExpanded, setIsExpanded] = useState(false);

  const appInfoFields = [
    { label: "Identifier", value: appDetails?.identifier },
    { label: "PID", value: appDetails?.pid },
    { label: "PPID", value: appDetails?.parameters?.ppid },
    { label: "Build", value: appDetails?.parameters?.build },
    { label: "Data Dir", value: appDetails?.parameters?.dataDir },
    { label: "Started", value: appDetails?.parameters?.started },
    { label: "Target SDK", value: appDetails?.parameters?.targetSdk },
    { label: "User", value: appDetails?.parameters?.user },
    { label: "Version", value: appDetails?.parameters?.version },
  ];

  return (
    <div className="bg-white rounded-xl shadow-sm mb-6 overflow-hidden">
      <div
        className="px-6 py-4 border-b border-gray-100 cursor-pointer hover:bg-gray-50 transition-colors"
        onClick={() => setIsExpanded(!isExpanded)}
      >
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-medium text-gray-800">App Information</h2>
          {isExpanded ? (
            <ChevronDownIcon size={20} color="gray" />
          ) : (
            <ChevronRightIcon size={20} color="gray" />
          )}
        </div>
      </div>

      {isExpanded && (
        <div className="p-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {appInfoFields.map(({ label, value }) => (
              <div key={label} className="bg-gray-50 rounded-lg p-4">
                <p className="text-sm font-medium text-gray-500">{label}</p>
                <p className="mt-1 text-sm font-mono text-gray-900 break-all">
                  {value || "—"}
                </p>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};

export default AppInformation;
