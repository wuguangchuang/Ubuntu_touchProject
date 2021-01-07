#ifndef DRAWPANEL_H
#define DRAWPANEL_H
#include <QQuickPaintedItem>
#include <QBrush>
#include <QPainter>
#include "sdk/tdebug.h"
class QDrawPanel : public QQuickPaintedItem
{
    Q_OBJECT
public:
    QDrawPanel(QQuickItem* parent = 0);
    void paint(QPainter *painter);
    void paintEvent(QPaintEvent *event);
    bool event(QEvent *e) Q_DECL_OVERRIDE;

private:
    QVariantList mFingers;

};


#endif // DRAWPANEL_H
