import React, { useEffect, useState, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import { useExclusions } from '../../hooks/useExclusions';
import { useConfirmDialog } from '../../hooks/useConfirmDialog';
import { pickScanFolder, pickScanFile } from '../../services/api';
import type { Exclusion, ExclusionType } from '../../types/exclusion';
import { TrashIcon, PlusIcon, EditIcon, EmptyExclusionIcon } from '../shared/Icons';
import { ConfirmDialog } from '../shared/ConfirmDialog';
import './ExclusionsManager.css';

const TYPE_LABEL_KEYS: Record<ExclusionType, string> = {
  path: 'exclusions.exactPath',
  folder: 'exclusions.folder',
  extension: 'exclusions.extension',
  pattern: 'exclusions.pattern',
};

const TYPE_PLACEHOLDER_KEYS: Record<ExclusionType, string> = {
  path: 'exclusions.pathPlaceholder',
  folder: 'exclusions.folderPlaceholder',
  extension: 'exclusions.extensionPlaceholder',
  pattern: 'exclusions.patternPlaceholder',
};

interface EditModalProps {
  exclusion: Exclusion;
  onSave: (updates: { pattern?: string; reason?: string }) => Promise<void>;
  onClose: () => void;
}

const EditModal: React.FC<EditModalProps> = ({ exclusion, onSave, onClose }) => {
  const { t } = useTranslation();
  const [pattern, setPattern] = useState(exclusion.pattern);
  const [reason, setReason] = useState(exclusion.reason || '');
  const [saving, setSaving] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      await onSave({
        pattern: pattern !== exclusion.pattern ? pattern : undefined,
        reason: reason !== exclusion.reason ? reason : undefined,
      });
      onClose();
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="exclusion-modal-overlay" onClick={onClose}>
      <div className="exclusion-modal" onClick={e => e.stopPropagation()}>
        <h3>{t('exclusions.editTitle')}</h3>
        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label>{t('exclusions.typeLabel')}</label>
            <input type="text" value={t(TYPE_LABEL_KEYS[exclusion.exclusion_type])} disabled />
          </div>
          <div className="form-group">
            <label>{t('exclusions.patternLabel')}</label>
            <input
              type="text"
              value={pattern}
              onChange={e => setPattern(e.target.value)}
              placeholder={t(TYPE_PLACEHOLDER_KEYS[exclusion.exclusion_type])}
              required
            />
          </div>
          <div className="form-group">
            <label>{t('exclusions.reasonLabel')}</label>
            <textarea
              value={reason}
              onChange={e => setReason(e.target.value)}
              placeholder={t('exclusions.reasonPlaceholder')}
            />
          </div>
          <div className="modal-actions">
            <button type="button" className="cancel-btn" onClick={onClose}>{t('exclusions.cancel')}</button>
            <button type="submit" className="save-btn" disabled={saving || !pattern.trim()}>
              {saving ? t('exclusions.saving') : t('exclusions.saveChanges')}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};

export const ExclusionsManager: React.FC = () => {
  const { t, i18n } = useTranslation();
  const {
    exclusions,
    loading,
    error,
    fetchExclusions,
    addExclusion,
    updateExclusion,
    toggleExclusion,
    deleteExclusion,
  } = useExclusions();

  const [newType, setNewType] = useState<ExclusionType>('folder');
  const [newPattern, setNewPattern] = useState('');
  const [newReason, setNewReason] = useState('');
  const [filterType, setFilterType] = useState<ExclusionType | 'all'>('all');
  const [editingExclusion, setEditingExclusion] = useState<Exclusion | null>(null);
  const [adding, setAdding] = useState(false);
  const [pickerLoading, setPickerLoading] = useState(false);
  const { confirm: confirmDialog, dialogProps } = useConfirmDialog();

  useEffect(() => {
    fetchExclusions();
  }, [fetchExclusions]);

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newPattern.trim()) return;
    
    setAdding(true);
    const success = await addExclusion({
      exclusion_type: newType,
      pattern: newPattern.trim(),
      reason: newReason.trim() || undefined,
    });
    
    if (success) {
      setNewPattern('');
      setNewReason('');
    }
    setAdding(false);
  };

  const handleToggle = async (id: number, currentEnabled: boolean) => {
    await toggleExclusion(id, !currentEnabled);
  };

  const handleDelete = async (id: number) => {
    if (await confirmDialog({
      title: t('exclusions.deleteTitle'),
      message: t('exclusions.deleteMessage'),
      confirmLabel: t('exclusions.deleteLabel'),
      variant: 'danger',
    })) {
      await deleteExclusion(id);
    }
  };

  const handleEdit = async (updates: { pattern?: string; reason?: string }) => {
    if (editingExclusion) {
      await updateExclusion({
        id: editingExclusion.id,
        ...updates,
      });
    }
  };

  const handleBrowseFolder = useCallback(async () => {
    try {
      setPickerLoading(true);
      const path = await pickScanFolder();
      if (path) setNewPattern(path);
    } catch (e) {
      console.error('Failed to pick folder:', e);
    } finally {
      setPickerLoading(false);
    }
  }, []);

  const handleBrowseFile = useCallback(async () => {
    try {
      setPickerLoading(true);
      const path = await pickScanFile();
      if (path) setNewPattern(path);
    } catch (e) {
      console.error('Failed to pick file:', e);
    } finally {
      setPickerLoading(false);
    }
  }, []);

  const filteredExclusions = filterType === 'all'
    ? exclusions
    : exclusions.filter(e => e.exclusion_type === filterType);

  const formatDate = (timestamp: number) => {
    return new Date(timestamp * 1000).toLocaleDateString(i18n.resolvedLanguage || i18n.language || undefined, {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    });
  };

  return (
    <div className="exclusions-manager">
      <div className="exclusions-header">
        <h2>{t('exclusions.title')}</h2>
        <p>{t('exclusions.description')}</p>
      </div>

      {error && (
        <div className="exclusions-error">{error}</div>
      )}

      <div className="exclusions-content">
        {/* Add Form */}
        <form className="exclusions-add-form" onSubmit={handleAdd}>
          <select value={newType} onChange={e => setNewType(e.target.value as ExclusionType)}>
            <option value="path">{t('exclusions.exactPath')}</option>
            <option value="folder">{t('exclusions.folder')}</option>
            <option value="extension">{t('exclusions.extension')}</option>
            <option value="pattern">{t('exclusions.pattern')}</option>
          </select>
          <div className="pattern-input-wrapper">
            <input
              type="text"
              className="pattern-input"
              value={newPattern}
              onChange={e => setNewPattern(e.target.value)}
              placeholder={t(TYPE_PLACEHOLDER_KEYS[newType])}
            />
            {(newType === 'path' || newType === 'folder') && (
              <>
                <button
                  type="button"
                  className="browse-btn"
                  onClick={handleBrowseFolder}
                  disabled={pickerLoading}
                  title={t('exclusions.browseFolder')}
                >
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
                  </svg>
                </button>
                {newType === 'path' && (
                  <button
                    type="button"
                    className="browse-btn"
                    onClick={handleBrowseFile}
                    disabled={pickerLoading}
                    title={t('exclusions.browseFile')}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                      <polyline points="14 2 14 8 20 8" />
                    </svg>
                  </button>
                )}
              </>
            )}
          </div>
          <input
            type="text"
            className="reason-input"
            value={newReason}
            onChange={e => setNewReason(e.target.value)}
            placeholder={t('exclusions.reasonInputPlaceholder')}
          />
          <button type="submit" className="add-btn" disabled={adding || !newPattern.trim() || pickerLoading}>
            <PlusIcon />
            {t('exclusions.add')}
          </button>
        </form>

        {/* Filter Tabs */}
        <div className="exclusions-filters">
          <button
            className={`filter-btn ${filterType === 'all' ? 'active' : ''}`}
            onClick={() => setFilterType('all')}
          >
            {t('exclusions.all')} ({exclusions.length})
          </button>
          <button
            className={`filter-btn ${filterType === 'path' ? 'active' : ''}`}
            onClick={() => setFilterType('path')}
          >
            {t('exclusions.paths')}
          </button>
          <button
            className={`filter-btn ${filterType === 'folder' ? 'active' : ''}`}
            onClick={() => setFilterType('folder')}
          >
            {t('exclusions.folders')}
          </button>
          <button
            className={`filter-btn ${filterType === 'extension' ? 'active' : ''}`}
            onClick={() => setFilterType('extension')}
          >
            {t('exclusions.extensions')}
          </button>
          <button
            className={`filter-btn ${filterType === 'pattern' ? 'active' : ''}`}
            onClick={() => setFilterType('pattern')}
          >
            {t('exclusions.patterns')}
          </button>
        </div>

        {/* List */}
        {loading ? (
          <div className="exclusions-loading">{t('exclusions.loadingExclusions')}</div>
        ) : filteredExclusions.length === 0 ? (
          <div className="exclusions-empty">
            <EmptyExclusionIcon />
            <h3>{t('exclusions.noExclusions')}</h3>
            <p>{t('exclusions.noExclusionsHint')}</p>
          </div>
        ) : (
          <div className="exclusions-list">
            {filteredExclusions.map(exclusion => (
              <div
                key={exclusion.id}
                className={`exclusion-item ${!exclusion.enabled ? 'disabled' : ''}`}
              >
                <div className="exclusion-toggle">
                  <input
                    type="checkbox"
                    checked={exclusion.enabled}
                    onChange={() => handleToggle(exclusion.id, exclusion.enabled)}
                    title={exclusion.enabled ? t('exclusions.disableExclusion') : t('exclusions.enableExclusion')}
                  />
                </div>
                <div className="exclusion-info">
                  <div className="exclusion-pattern">{exclusion.pattern}</div>
                  <div className="exclusion-meta">
                    <span className={`exclusion-type ${exclusion.exclusion_type}`}>
                      {t(TYPE_LABEL_KEYS[exclusion.exclusion_type])}
                    </span>
                    {exclusion.reason && (
                      <span className="exclusion-reason" title={exclusion.reason}>
                        {exclusion.reason}
                      </span>
                    )}
                    <span>{t('exclusions.added', { date: formatDate(exclusion.created_at) })}</span>
                  </div>
                </div>
                <div className="exclusion-actions">
                  <button onClick={() => setEditingExclusion(exclusion)} title={t('exclusions.editTitle')}>
                    <EditIcon />
                  </button>
                  <button className="delete-btn" onClick={() => handleDelete(exclusion.id)} title={t('exclusions.deleteLabel')}>
                    <TrashIcon />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Edit Modal */}
      {editingExclusion && (
        <EditModal
          exclusion={editingExclusion}
          onSave={handleEdit}
          onClose={() => setEditingExclusion(null)}
        />
      )}

      <ConfirmDialog {...dialogProps} />
    </div>
  );
};

export default ExclusionsManager;
