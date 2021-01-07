#include "include/drawpanel.h"

#include <QCursor>
#include "sdk/tdebug.h"
#define CURRENT_POINT   "current"
#define TOUCH_POINTS    "points"
QDrawPanel::QDrawPanel(QQuickItem* parent)
    : QQuickPaintedItem(parent)
{
    this->setActiveFocusOnTab(false);
    this->setAcceptedMouseButtons(Qt::AllButtons);
    QVariantMap finger;
    finger.insert(CURRENT_POINT, 0);
    mFingers.append(finger);
}

void QDrawPanel::paintEvent(QPaintEvent *event)
{
    TINFO("paint event ");
}

void QDrawPanel::paint(QPainter *painter)
{

    QBrush brush(QColor("#ffffff"));
    QVariantMap finger = mFingers.at(0).value<QVariantMap>();

    QVariantList points =
            finger.value(TOUCH_POINTS, QVariantList()).value<QVariantList>();
//    TDEBUG("point count: %d", points.count());
    if (points.count() == 0)
        return;
    int current = finger.value(CURRENT_POINT).toInt();
    int i;
    painter->setBrush(QBrush(QColor(123,123,123)));
    painter->setPen(QColor(190,123,110));
    int lastx = -1, lasty = -1, x, y;
    for (i = 0; i < points.count(); i++) {
        QVariantMap point = points.at(i).value<QVariantMap>();
        x = point.value("x", 0).toInt();
        y = point.value("y", 0).toInt();
        if (lastx != -1) {
            painter->drawLine(lastx, lasty, x, y);
        }
        lastx = x;
        lasty = y;
        QRectF rect(x, y, 5, 5);
        painter->drawEllipse(rect);
    }
    finger.insert(CURRENT_POINT, i);
    mFingers.replace(0, finger);
}

bool QDrawPanel::event(QEvent *e)
{
    bool touchBegin = false;
//    TINFO("%s: %d", __func__, e->type());
    switch (e->type()) {
    case QEvent::TouchBegin:
        touchBegin = true;
    case QEvent::MouseMove: {
        QPoint point;
        const QMouseEvent *const event = static_cast<const QMouseEvent*>(e);
//        point = QCursor::pos();
        point = event->pos();
        QVariantMap finger = mFingers.at(0).value<QVariantMap>();
        QVariantList points =
                finger.value("points", QVariantList()).value<QVariantList>();
        QVariantMap p;
        p.insert("x", QVariant::fromValue(point.x()));
        p.insert("y", QVariant::fromValue(point.y()));
        p.insert("id",QVariant::fromValue(0));
        points.append(p);
        finger.insert("points", points);
        mFingers.replace(0, finger);

//        QRectF rect(point.x, point.y, 1, 1);
        int rad = 2;
//        update(QRect(point.x() - 5, point.y() - 5, 10, 10));
        update();
        TINFO("touch move");
//        update(rect.toRect().adjusted(-rad,-rad, +rad, +rad));
//        update();
        break;
    }
    case QEvent::TouchUpdate:
    {
        const QTouchEvent *const event = static_cast<const QTouchEvent*>(e);
        const QList<QTouchEvent::TouchPoint> points = event->touchPoints();
        foreach (const QTouchEvent::TouchPoint &touchPoint, points) {
            const int id = touchPoint.id();
            switch (touchPoint.state()) {
            case Qt::TouchPointPressed:
            {

                break;
            }
            case Qt::TouchPointReleased:
            {

                break;
            }
            case Qt::TouchPointMoved:
            {
                QTouchEvent::TouchPoint point = points.at(0);
                QVariantMap finger = mFingers.at(0).value<QVariantMap>();
                QVariantList points =
                        finger.value("points", QVariantList()).value<QVariantList>();
                QVariantMap p;
                p.insert("x", 1);//QVariant::fromValue(point.pos().x));
                p.insert("y", 2);//QVariant::fromValue(point.pos().y));
                p.insert("id", 3);//QVariant::fromValue(point.id));
                points.append(p);
                QRectF rect = point.rect();
                int rad = 2;
                TINFO("touch move");
                update(rect.toRect().adjusted(-rad,-rad, +rad, +rad));

                break;
            }
            default:
                break;
            }
        }
    }
        break;
    case QEvent::TouchEnd:
        return true;
        break;
    default:
        break;
    }
    return true;
}
