import { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileJson, Loader2 } from 'lucide-react';

interface CBOMUploaderProps {
  onUpload: (file: File) => void;
  isLoading: boolean;
}

export default function CBOMUploader({ onUpload, isLoading }: CBOMUploaderProps) {
  const [fileName, setFileName] = useState<string | null>(null);

  const onDrop = useCallback((acceptedFiles: File[]) => {
    if (acceptedFiles.length > 0) {
      setFileName(acceptedFiles[0].name);
      onUpload(acceptedFiles[0]);
    }
  }, [onUpload]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: { 'application/json': ['.json'] },
    maxFiles: 1,
    disabled: isLoading,
  });

  return (
    <div
      {...getRootProps()}
      className={`
        border-2 border-dashed rounded-lg p-12 text-center cursor-pointer
        transition-all duration-200
        ${isDragActive
          ? 'border-qg-accent bg-qg-accent/5'
          : 'border-qg-border hover:border-gray-500 hover:bg-qg-card/50'
        }
        ${isLoading ? 'opacity-50 cursor-wait' : ''}
      `}
    >
      <input {...getInputProps()} />
      {isLoading ? (
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="w-10 h-10 text-qg-accent animate-spin" />
          <p className="text-gray-500">Processing {fileName}...</p>
        </div>
      ) : fileName ? (
        <div className="flex flex-col items-center gap-3">
          <FileJson className="w-10 h-10 text-qg-green" />
          <p className="text-qg-green">{fileName} loaded</p>
          <p className="text-gray-500 text-sm">Drop another file to replace</p>
        </div>
      ) : (
        <div className="flex flex-col items-center gap-3">
          <Upload className="w-10 h-10 text-qg-accent" />
          <p className="text-qg-accent text-lg font-medium">
            Drop a CBOM here to visualize it
          </p>
          <p className="text-gray-500 text-sm">(or click to browse)</p>
        </div>
      )}
    </div>
  );
}
