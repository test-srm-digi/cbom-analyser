import { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { Upload, FileJson, Loader2 } from 'lucide-react';
import styles from './CBOMUploader.module.scss';

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

  const dropzoneClass = [
    styles.dropzone,
    isDragActive ? styles.dropzoneActive : '',
    isLoading ? styles.dropzoneLoading : '',
  ].filter(Boolean).join(' ');

  return (
    <div {...getRootProps()} className={dropzoneClass}>
      <input {...getInputProps()} />
      {isLoading ? (
        <div className={styles.inner}>
          <Loader2 className={styles.iconSpin} />
          <p className={styles.subText}>Processing {fileName}...</p>
        </div>
      ) : fileName ? (
        <div className={styles.inner}>
          <FileJson className={styles.iconSuccess} />
          <p className={styles.mainTextSuccess}>{fileName} loaded</p>
          <p className={styles.subText}>Drop another file to replace</p>
        </div>
      ) : (
        <div className={styles.inner}>
          <Upload className={styles.icon} />
          <p className={styles.mainText}>Drop a CBOM here to visualize it</p>
          <p className={styles.subText}>(or click to browse)</p>
        </div>
      )}
    </div>
  );
}
